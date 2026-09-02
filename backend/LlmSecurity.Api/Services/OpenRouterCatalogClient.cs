using System.Net.Http.Headers;
using System.Text.Json;
using LlmSecurity.Api.DTOs;

namespace LlmSecurity.Api.Services;

public sealed class OpenRouterCatalogClient(HttpClient http)
{
    public async Task<List<OpenRouterModelResponse>> GetModelsAsync(
        string apiKey,
        CancellationToken cancellationToken = default)
    {
        var normalizedKey = apiKey.Trim();
        if (normalizedKey.Length is < 8 or > 512 || normalizedKey.Any(char.IsWhiteSpace))
            throw new ArgumentException("유효한 OpenRouter API Key를 입력해주세요.");

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            "/api/v1/models?output_modalities=text");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", normalizedKey);

        using var response = await http.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new OpenRouterCatalogException(response.StatusCode);

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);

        if (!document.RootElement.TryGetProperty("data", out var data) ||
            data.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException("OpenRouter 모델 목록 응답 형식이 올바르지 않습니다.");
        }

        var models = new List<OpenRouterModelResponse>();
        foreach (var item in data.EnumerateArray())
        {
            var id = GetString(item, "id");
            if (string.IsNullOrWhiteSpace(id))
                continue;

            var supported = item.TryGetProperty("supported_parameters", out var parameters) &&
                parameters.ValueKind == JsonValueKind.Array
                ? parameters.EnumerateArray()
                    .Where(value => value.ValueKind == JsonValueKind.String)
                    .Select(value => value.GetString() ?? "")
                    .ToHashSet(StringComparer.OrdinalIgnoreCase)
                : [];

            int? contextLength = null;
            if (item.TryGetProperty("context_length", out var context) &&
                context.TryGetInt32(out var parsedContext))
            {
                contextLength = parsedContext;
            }

            string? promptPrice = null;
            string? completionPrice = null;
            if (item.TryGetProperty("pricing", out var pricing) &&
                pricing.ValueKind == JsonValueKind.Object)
            {
                promptPrice = GetString(pricing, "prompt");
                completionPrice = GetString(pricing, "completion");
            }

            models.Add(new OpenRouterModelResponse(
                id,
                GetString(item, "name") ?? id,
                contextLength,
                promptPrice,
                completionPrice,
                supported.Contains("structured_outputs") ||
                supported.Contains("response_format")));
        }

        return models
            .OrderBy(model => model.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string? GetString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}

public sealed class OpenRouterCatalogException(System.Net.HttpStatusCode statusCode)
    : Exception("OpenRouter API Key를 확인하거나 잠시 후 다시 시도해주세요.")
{
    public System.Net.HttpStatusCode StatusCode { get; } = statusCode;
}
