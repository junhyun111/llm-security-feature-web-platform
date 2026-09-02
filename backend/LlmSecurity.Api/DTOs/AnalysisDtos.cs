using System.Text.Json;

namespace LlmSecurity.Api.DTOs;

public record AnalysisJobResponse(
    Guid Id,
    string ProjectName,
    string ModelId,
    double Sensitivity,
    string Status,
    int Progress,
    string Message,
    int FileCount,
    int SourceFileCount,
    int FindingCount,
    int ValidatedFindingCount,
    double TotalCost,
    string? ErrorMessage,
    DateTime CreatedAt,
    DateTime UpdatedAt,
    DateTime? CompletedAt
);

public record AnalysisDetailResponse(
    AnalysisJobResponse Job,
    JsonElement? Analysis
);

public record PatchProposalRequest(List<string> FindingIds, string ApiKey);

public record OpenRouterModelsRequest(string ApiKey);

public record OpenRouterModelResponse(
    string Id,
    string Name,
    int? ContextLength,
    string? PromptPrice,
    string? CompletionPrice,
    bool SupportsStructuredOutput
);

public record DashboardResponse(
    int TotalScans,
    int CompletedScans,
    int TotalFindings,
    int ValidatedFindings,
    int ApprovedPatches,
    List<AnalysisJobResponse> RecentJobs
);
