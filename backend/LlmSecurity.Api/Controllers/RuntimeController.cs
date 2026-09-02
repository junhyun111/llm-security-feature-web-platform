using LlmSecurity.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace LlmSecurity.Api.Controllers;

[Authorize]
[ApiController]
[Route("api/runtime")]
public class RuntimeController : ApiControllerBase
{
    private readonly PythonAnalyzerClient _analyzer;

    public RuntimeController(PythonAnalyzerClient analyzer)
    {
        _analyzer = analyzer;
    }

    [HttpGet]
    public async Task<IActionResult> Get(CancellationToken cancellationToken)
    {
        try
        {
            var json = await _analyzer.GetRuntimeMetadataJsonAsync(cancellationToken);
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
                "Python 분석 서버에 연결할 수 없습니다.",
                "RUNTIME_UNAVAILABLE");
        }
    }
}
