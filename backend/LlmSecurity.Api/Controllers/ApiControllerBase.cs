using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace LlmSecurity.Api.Controllers;

public abstract class ApiControllerBase : ControllerBase
{
    protected ObjectResult ApiProblem(
        int status,
        string detail,
        string code,
        IEnumerable<string>? errors = null)
    {
        var traceId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;
        var problem = new ProblemDetails
        {
            Status = status,
            Title = status switch
            {
                400 => "Bad Request",
                401 => "Unauthorized",
                403 => "Forbidden",
                404 => "Not Found",
                409 => "Conflict",
                429 => "Too Many Requests",
                503 => "Service Unavailable",
                _ when status >= 500 => "Internal Server Error",
                _ => "Request Failed"
            },
            Detail = detail,
            Instance = HttpContext.Request.Path
        };
        problem.Extensions["code"] = code;
        problem.Extensions["traceId"] = traceId;
        if (errors is not null)
            problem.Extensions["errors"] = errors.ToArray();
        return new ObjectResult(problem) { StatusCode = status };
    }
}
