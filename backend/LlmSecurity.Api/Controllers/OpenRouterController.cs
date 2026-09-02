using LlmSecurity.Api.DTOs;
using LlmSecurity.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace LlmSecurity.Api.Controllers;

[Authorize]
[ApiController]
[Route("api/openrouter")]
public sealed class OpenRouterController(OpenRouterCatalogClient catalog) : ApiControllerBase
{
    [HttpPost("models")]
    public async Task<IActionResult> Models(
        OpenRouterModelsRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            return Ok(await catalog.GetModelsAsync(request.ApiKey, cancellationToken));
        }
        catch (ArgumentException error)
        {
            return ApiProblem(400, error.Message, "OPENROUTER_REQUEST_INVALID");
        }
        catch (OpenRouterCatalogException error)
        {
            return ApiProblem(
                (int)error.StatusCode,
                error.Message,
                "OPENROUTER_REQUEST_FAILED");
        }
        catch (HttpRequestException)
        {
            return ApiProblem(
                503,
                "OpenRouter 모델 목록을 불러올 수 없습니다.",
                "OPENROUTER_UNAVAILABLE");
        }
    }
}
