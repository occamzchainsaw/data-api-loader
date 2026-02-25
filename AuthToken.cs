namespace DataApiLoader;

public class AuthToken
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; } = DateTime.MinValue;
    public DateTime RefreshTokenExpiresAt { get; set; } = DateTime.MinValue;
    public bool IsError { get; set; }
    public string ErrorMessage { get; set; } = string.Empty;

    public static AuthToken Error(string message) =>
        new() { IsError = true, ErrorMessage = message };
}
