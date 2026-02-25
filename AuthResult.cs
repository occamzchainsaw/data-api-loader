namespace DataApiLoader;

public record AuthResult
{
    public string Code { get; init; } = string.Empty;
    public bool IsError { get; init; } = false;
    public string ErrorMessage { get; init; } = string.Empty;

    public static AuthResult Error(string message) =>
        new() { IsError = true, ErrorMessage = message };
}
