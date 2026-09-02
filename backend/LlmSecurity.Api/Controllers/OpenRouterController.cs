using LlmSecurity.Api.DTOs;
using LlmSecurity.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace LlmSecurity.Api.Controllers;

[Authorize]
[ApiController]
[Route("api/openrouter")]
public sealed class OpenRouterController(OpenRouterCatalogClient catalog) : ControllerBase
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
            return BadRequest(new { message = error.Message });
        }
        catch (OpenRouterCatalogException error)
        {
            return StatusCode((int)error.StatusCode, new { message = error.Message });
        }
        catch (HttpRequestException)
        {
            return StatusCode(
                StatusCodes.Status503ServiceUnavailable,
                new { message = "OpenRouter 모델 목록을 불러올 수 없습니다." });
        }
    }
}
