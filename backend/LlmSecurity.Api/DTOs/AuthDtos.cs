namespace LlmSecurity.Api.DTOs;

public record RegisterRequest(string Email, string Password, string DisplayName);
public record LoginRequest(string Email, string Password);
public record UserResponse(string Id, string Email, string DisplayName);
public record UpdateProfileRequest(string Email, string DisplayName);
public record ChangePasswordRequest(string CurrentPassword, string NewPassword);
