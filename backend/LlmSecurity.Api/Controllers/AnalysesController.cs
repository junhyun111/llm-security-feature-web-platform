using System.Net;
using System.Diagnostics;
using System.Text.Json;
using LlmSecurity.Api.Data;
using LlmSecurity.Api.DTOs;
using LlmSecurity.Api.Models;
using LlmSecurity.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LlmSecurity.Api.Controllers;

[Authorize]
[ApiController]
[Route("api/analyses")]
public class AnalysesController : ApiControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly UserManager<AppUser> _userManager;
    private readonly PythonAnalyzerClient _analyzer;
    private readonly AnalysisSyncService _sync;
    private readonly ILogger<AnalysesController> _logger;

    public AnalysesController(
        ApplicationDbContext db,
        UserManager<AppUser> userManager,
        PythonAnalyzerClient analyzer,
        AnalysisSyncService sync,
        ILogger<AnalysesController> logger)
    {
        _db = db;
        _userManager = userManager;
        _analyzer = analyzer;
        _sync = sync;
        _logger = logger;
    }

    [HttpGet]
    public async Task<ActionResult<List<AnalysisJobResponse>>> List(
        CancellationToken cancellationToken)
    {
        var userId = _userManager.GetUserId(User)!;

        var entities = await _db.AnalysisJobs
            .AsNoTracking()
            .Where(x => x.UserId == userId)
            .OrderByDescending(x => x.CreatedAt)
            .ToListAsync(cancellationToken);

        return Ok(entities.Select(ToResponse).ToList());
    }

    [HttpPost]
    [RequestFormLimits(MultipartBodyLengthLimit = 1_200_000_000)]
    [RequestSizeLimit(1_200_000_000)]
    public async Task<ActionResult<AnalysisJobResponse>> Create(
        [FromForm(Name = "project_name")] string projectName,
        [FromForm(Name = "sensitivity")] double sensitivity,
        [FromForm(Name = "model")] string model,
        [FromForm(Name = "api_key")] string apiKey,
        [FromForm(Name = "relative_paths")] List<string> relativePaths,
        [FromForm(Name = "files")] List<IFormFile> files,
        CancellationToken cancellationToken)
    {
        if (files.Count == 0)
            return ApiProblem(400, "분석할 파일을 선택해주세요.", "ANALYSIS_FILES_REQUIRED");

        if (files.Count != relativePaths.Count)
            return ApiProblem(400, "파일과 상대 경로 개수가 일치하지 않습니다.", "ANALYSIS_FILE_PATH_MISMATCH");

        try
        {
            var remote = await _analyzer.CreateJobAsync(
                projectName,
                files,
                relativePaths,
                sensitivity,
                model,
                apiKey,
                cancellationToken);

            var job = new AnalysisJob
            {
                UserId = _userManager.GetUserId(User)!,
                AnalyzerJobId = remote.JobId,
                ProjectName = remote.ProjectName,
                ModelId = model.Trim(),
                Sensitivity = sensitivity,
                Status = remote.Status,
                Progress = remote.Progress,
                Message = remote.Message,
                FileCount = remote.FileCount,
                SourceFileCount = remote.SourceFileCount,
                FindingCount = remote.FindingCount,
                ValidatedFindingCount = remote.ValidatedFindingCount,
                TotalCost = remote.TotalCost,
                ErrorMessage = remote.Error
            };

            _db.AnalysisJobs.Add(job);
            await _db.SaveChangesAsync(cancellationToken);

            return Accepted(ToResponse(job));
        }
        catch (AnalyzerApiException ex)
        {
            return ApiProblem((int)ex.StatusCode, ex.Message, "ANALYZER_REQUEST_FAILED");
        }
        catch (HttpRequestException)
        {
            return ApiProblem(
                503,
                "Python 분석 서버에 연결할 수 없습니다. 분석 서버가 실행 중인지 확인해주세요.",
                "RUNTIME_UNAVAILABLE");
        }
    }

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<AnalysisDetailResponse>> Get(
        Guid id,
        CancellationToken cancellationToken)
    {
        var job = await GetOwnedJob(id, cancellationToken);
        if (job is null)
            return NotFound();

        var sync = CachedSync(job);
        if (NeedsDetailSync(job))
        {
            sync = await _sync.TrySyncAsync(
                job,
                includeAnalysis: true,
                cancellationToken);
            job = sync.Job;
        }

        JsonElement? analysis = null;

        if (!string.IsNullOrWhiteSpace(job.AnalysisJson))
        {
            try
            {
                using var doc = JsonDocument.Parse(job.AnalysisJson);
                analysis = doc.RootElement.Clone();
            }
            catch (JsonException error)
            {
                var traceId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;
                _logger.LogError(
                    error,
                    "Stored analysis JSON is invalid for {AnalysisId}; traceId={TraceId}",
                    job.Id,
                    traceId);
                sync = sync with
                {
                    State = "stale",
                    Warning = "저장된 분석 결과를 일시적으로 불러오지 못했습니다.",
                    TraceId = traceId
                };
            }
        }

        return Ok(new AnalysisDetailResponse(
            ToResponse(job),
            analysis,
            ToSyncInfo(sync)));
    }

    [HttpGet("{id:guid}/status")]
    public async Task<ActionResult<AnalysisStatusResponse>> Status(
        Guid id,
        CancellationToken cancellationToken)
    {
        var job = await GetOwnedJob(id, cancellationToken);
        if (job is null)
            return NotFound();

        var sync = CachedSync(job);
        if (IsActive(job.Status))
        {
            sync = await _sync.TrySyncAsync(
                job,
                includeAnalysis: false,
                cancellationToken);
            job = sync.Job;
        }

        return Ok(new AnalysisStatusResponse(
            ToResponse(job),
            ToSyncInfo(sync)));
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(
        Guid id,
        CancellationToken cancellationToken)
    {
        var job = await GetOwnedJob(id, cancellationToken);
        if (job is null)
            return NotFound();

        if (IsActive(job.Status))
        {
            return ApiProblem(
                409,
                "진행 중인 분석은 완료 또는 실패 후 삭제할 수 있습니다.",
                "ANALYSIS_ACTIVE");
        }

        try
        {
            await _analyzer.DeleteJobAsync(job.AnalyzerJobId, cancellationToken);
        }
        catch (AnalyzerApiException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
        {
            // Runtime 파일이 이미 정리된 경우에도 사용자 이력은 삭제한다.
        }
        catch (AnalyzerApiException ex)
        {
            return ApiProblem((int)ex.StatusCode, ex.Message, "ANALYZER_REQUEST_FAILED");
        }
        catch (HttpRequestException)
        {
            return ApiProblem(
                503,
                "Python 분석 서버에 연결할 수 없어 이력을 안전하게 삭제하지 못했습니다.",
                "RUNTIME_UNAVAILABLE");
        }

        _db.AnalysisJobs.Remove(job);
        await _db.SaveChangesAsync(cancellationToken);
        return NoContent();
    }

    [HttpPost("{id:guid}/cancel")]
    public async Task<ActionResult<AnalysisJobResponse>> Cancel(
        Guid id,
        CancellationToken cancellationToken)
    {
        var job = await GetOwnedJob(id, cancellationToken);
        if (job is null)
            return NotFound();

        if (job.Status is not ("uploading" or "queued" or "analyzing" or "cancelling"))
        {
            return ApiProblem(409, "진행 중인 분석만 중단할 수 있습니다.", "ANALYSIS_NOT_ACTIVE");
        }

        try
        {
            var remote = await _analyzer.CancelJobAsync(
                job.AnalyzerJobId,
                cancellationToken);
            job.Status = remote.Status;
            job.Progress = remote.Progress;
            job.Message = remote.Message;
            job.ErrorMessage = remote.Error;
            job.UpdatedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync(cancellationToken);
            return Ok(ToResponse(job));
        }
        catch (AnalyzerApiException ex)
        {
            return ApiProblem((int)ex.StatusCode, ex.Message, "ANALYZER_REQUEST_FAILED");
        }
        catch (HttpRequestException)
        {
            return ApiProblem(
                503,
                "Python 분석 서버에 연결할 수 없어 중단 요청을 전달하지 못했습니다.",
                "RUNTIME_UNAVAILABLE");
        }
    }

    [HttpPost("{id:guid}/patches/proposal")]
    public async Task<IActionResult> ProposePatch(
        Guid id,
        PatchProposalRequest request,
        CancellationToken cancellationToken)
    {
        var job = await GetOwnedJob(id, cancellationToken);
        if (job is null)
            return NotFound();

        if (request.FindingIds.Count == 0)
            return ApiProblem(400, "수정할 취약점을 하나 이상 선택해주세요.", "FINDINGS_REQUIRED");

        try
        {
            var patchJson = await _analyzer.ProposePatchAsync(
                job.AnalyzerJobId,
                request.FindingIds,
                job.ModelId,
                request.ApiKey,
                cancellationToken);

            await _sync.StorePatchResponseAsync(job, patchJson, cancellationToken);

            return Content(patchJson, "application/json");
        }
        catch (AnalyzerApiException ex)
        {
            return ApiProblem((int)ex.StatusCode, ex.Message, "ANALYZER_REQUEST_FAILED");
        }
    }

    [HttpGet("{id:guid}/files")]
    public async Task<IActionResult> Files(
        Guid id,
        [FromQuery] string version = "original",
        CancellationToken cancellationToken = default)
    {
        var job = await GetOwnedJob(id, cancellationToken);
        if (job is null)
            return NotFound();

        try
        {
            var json = await _analyzer.GetProjectFilesJsonAsync(
                job.AnalyzerJobId,
                version,
                cancellationToken);
            return Content(json, "application/json");
        }
        catch (AnalyzerApiException ex)
        {
            return ApiProblem((int)ex.StatusCode, ex.Message, "ANALYZER_REQUEST_FAILED");
        }
        catch (HttpRequestException)
        {
            return ApiProblem(
                503,
                "분석 Runtime에서 소스 파일 목록을 불러올 수 없습니다.",
                "RUNTIME_UNAVAILABLE");
        }
    }

    [HttpGet("{id:guid}/files/content")]
    public async Task<IActionResult> FileContent(
        Guid id,
        [FromQuery] string path,
        [FromQuery] string version = "original",
        CancellationToken cancellationToken = default)
    {
        var job = await GetOwnedJob(id, cancellationToken);
        if (job is null)
            return NotFound();
        if (string.IsNullOrWhiteSpace(path))
            return ApiProblem(400, "조회할 소스 파일 경로를 입력해주세요.", "FILE_PATH_REQUIRED");

        try
        {
            var json = await _analyzer.GetProjectFileJsonAsync(
                job.AnalyzerJobId,
                path,
                version,
                cancellationToken);
            return Content(json, "application/json");
        }
        catch (AnalyzerApiException ex)
        {
            return ApiProblem((int)ex.StatusCode, ex.Message, "ANALYZER_REQUEST_FAILED");
        }
        catch (HttpRequestException)
        {
            return ApiProblem(
                503,
                "분석 Runtime에서 소스 파일을 불러올 수 없습니다.",
                "RUNTIME_UNAVAILABLE");
        }
    }

    [HttpGet("{id:guid}/patches/{patchId}/preview/content")]
    public async Task<IActionResult> PatchPreviewContent(
        Guid id,
        string patchId,
        [FromQuery] string path,
        CancellationToken cancellationToken)
    {
        var job = await GetOwnedJob(id, cancellationToken);
        if (job is null)
            return NotFound();
        if (string.IsNullOrWhiteSpace(path))
            return ApiProblem(400, "미리 볼 소스 파일 경로를 입력해주세요.", "FILE_PATH_REQUIRED");

        try
        {
            var json = await _analyzer.GetPatchPreviewFileJsonAsync(
                job.AnalyzerJobId,
                patchId,
                path,
                cancellationToken);
            return Content(json, "application/json");
        }
        catch (AnalyzerApiException ex)
        {
            return ApiProblem((int)ex.StatusCode, ex.Message, "ANALYZER_REQUEST_FAILED");
        }
        catch (HttpRequestException)
        {
            return ApiProblem(
                503,
                "패치 미리보기를 생성할 수 없습니다.",
                "RUNTIME_UNAVAILABLE");
        }
    }

    [HttpPost("{id:guid}/patches/{patchId}/{action}")]
    public async Task<IActionResult> PatchAction(
        Guid id,
        string patchId,
        string action,
        CancellationToken cancellationToken)
    {
        var job = await GetOwnedJob(id, cancellationToken);
        if (job is null)
            return NotFound();

        if (action is not ("approve" or "reject"))
            return ApiProblem(400, "지원하지 않는 패치 작업입니다.", "PATCH_ACTION_INVALID");

        try
        {
            var patchJson = await _analyzer.PatchActionAsync(
                job.AnalyzerJobId,
                patchId,
                action,
                cancellationToken);

            await _sync.StorePatchResponseAsync(job, patchJson, cancellationToken);

            return Content(patchJson, "application/json");
        }
        catch (AnalyzerApiException ex)
        {
            return ApiProblem((int)ex.StatusCode, ex.Message, "ANALYZER_REQUEST_FAILED");
        }
    }

    [HttpGet("{id:guid}/download")]
    public async Task<IActionResult> Download(
        Guid id,
        CancellationToken cancellationToken)
    {
        var job = await GetOwnedJob(id, cancellationToken);
        if (job is null)
            return NotFound();

        try
        {
            using var response = await _analyzer.DownloadAsync(
                job.AnalyzerJobId,
                cancellationToken);

            var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            var safeName = string.Concat(job.ProjectName.Select(c =>
                char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '-')).Trim('-');

            if (string.IsNullOrWhiteSpace(safeName))
                safeName = "project";

            return File(
                bytes,
                "application/zip",
                $"{safeName}-reviewed.zip");
        }
        catch (AnalyzerApiException ex)
        {
            return ApiProblem((int)ex.StatusCode, ex.Message, "ANALYZER_REQUEST_FAILED");
        }
    }

    private async Task<AnalysisJob?> GetOwnedJob(
        Guid id,
        CancellationToken cancellationToken)
    {
        var userId = _userManager.GetUserId(User)!;

        return await _db.AnalysisJobs
            .SingleOrDefaultAsync(
                x => x.Id == id && x.UserId == userId,
                cancellationToken);
    }

    private static bool IsActive(string status) =>
        status is "uploading" or "queued" or "analyzing" or "cancelling";

    private static bool NeedsDetailSync(AnalysisJob job) =>
        IsActive(job.Status) ||
        (job.Status is "completed" or "partial" or "cancelled" &&
         string.IsNullOrWhiteSpace(job.AnalysisJson));

    private static AnalysisSyncResult CachedSync(AnalysisJob job) => new(
        job,
        "fresh",
        null,
        job.UpdatedAt,
        null);

    private static AnalysisSyncInfo ToSyncInfo(AnalysisSyncResult sync) => new(
        sync.State,
        sync.Warning,
        sync.LastSuccessfulSyncAt,
        sync.TraceId);

    private static AnalysisJobResponse ToResponse(AnalysisJob x) => new(
        x.Id,
        x.ProjectName,
        x.ModelId,
        x.Sensitivity,
        x.Status,
        x.Progress,
        x.Message,
        x.FileCount,
        x.SourceFileCount,
        x.FindingCount,
        x.ValidatedFindingCount,
        x.TotalCost,
        x.ErrorMessage,
        x.CreatedAt,
        x.UpdatedAt,
        x.CompletedAt);
}
