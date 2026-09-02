using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace LlmSecurity.Api.Services;

public sealed class GlobalExceptionHandler : IExceptionHandler
{
    private readonly ILogger<GlobalExceptionHandler> _logger;

    public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger)
    {
        _logger = logger;
    }

    public async ValueTask<bool> TryHandleAsync(
        HttpContext context,
        Exception exception,
        CancellationToken cancellationToken)
    {
        var (status, title, detail, code) = exception switch
        {
            AnalyzerApiException analyzer => (
                (int)analyzer.StatusCode,
                "Analyzer request failed",
                analyzer.Message,
                "ANALYZER_REQUEST_FAILED"),
            BadHttpRequestException badRequest => (
                StatusCodes.Status400BadRequest,
                "Bad Request",
                badRequest.Message,
                "BAD_REQUEST"),
            UnauthorizedAccessException => (
                StatusCodes.Status403Forbidden,
                "Forbidden",
                "요청한 작업을 수행할 권한이 없습니다.",
                "FORBIDDEN"),
            HttpRequestException => (
                StatusCodes.Status503ServiceUnavailable,
                "Service Unavailable",
                "분석 Runtime과 통신하는 중 일시적인 오류가 발생했습니다.",
                "RUNTIME_UNAVAILABLE"),
            JsonException => (
                StatusCodes.Status500InternalServerError,
                "Internal Server Error",
                "저장된 분석 데이터를 처리하는 중 오류가 발생했습니다.",
                "ANALYSIS_DATA_ERROR"),
            _ => (
                StatusCodes.Status500InternalServerError,
                "Internal Server Error",
                "요청을 처리하는 중 내부 오류가 발생했습니다.",
                "BACKEND_INTERNAL_ERROR")
        };

        var traceId = Activity.Current?.Id ?? context.TraceIdentifier;
        if (status >= 500)
        {
            _logger.LogError(
                exception,
                "Unhandled backend error; status={Status}; code={Code}; traceId={TraceId}",
                status,
                code,
                traceId);
        }
        else
        {
            _logger.LogWarning(
                exception,
                "Backend request error; status={Status}; code={Code}; traceId={TraceId}",
                status,
                code,
                traceId);
        }

        context.Response.StatusCode = status;
        var problem = new ProblemDetails
        {
            Status = status,
            Title = title,
            Detail = detail,
            Instance = context.Request.Path
        };
        problem.Extensions["code"] = code;
        problem.Extensions["traceId"] = traceId;

        await context.Response.WriteAsJsonAsync(problem, cancellationToken);
        return true;
    }
}
