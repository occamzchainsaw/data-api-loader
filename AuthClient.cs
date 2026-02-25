using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DataApiLoader;

public class AuthClient
{
    private const string Scope = @"iracing.auth";

    private const string BaseAuthUrl = @"https://oauth.iracing.com/oauth2";
    private const string AuthEndpoint = $@"{BaseAuthUrl}/authorize";
    private const string TokenEndpoint = $@"{BaseAuthUrl}/token";
    private const string LoopbackAddress = @"127.0.0.1";

    private TcpListener? _listener;
    private string? _redirectUri;

    private string _state = string.Empty;
    private string? _clientId;
    private string? _codeVerifier;
    private string? _codeChallenge;

    [MemberNotNullWhen(
        true,
        nameof(_listener),
        nameof(_redirectUri),
        nameof(_clientId),
        nameof(_codeVerifier),
        nameof(_codeChallenge)
    )]
    public bool IsInitialized { get; private set; }

    [MemberNotNull(
        nameof(_listener),
        nameof(_redirectUri),
        nameof(_clientId),
        nameof(_codeVerifier),
        nameof(_codeChallenge)
    )]
    public void Initialize(string clientId, string redirectEndpoint)
    {
        _clientId = clientId;
        _listener = new(IPAddress.Parse(LoopbackAddress), 0);
        _listener.Start();

        int port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        string endpoint = redirectEndpoint.StartsWith('/')
            ? redirectEndpoint
            : "/" + redirectEndpoint;
        _redirectUri = $"http://{LoopbackAddress}:{port}{endpoint}";

        _codeVerifier = GenerateCodeVerifier();
        _codeChallenge = GenerateCodeChallenge(_codeVerifier);

        IsInitialized = true;
    }

    public void Stop()
    {
        if (!IsInitialized)
            throw new InvalidOperationException("Not initialized");

        _listener.Stop();
        IsInitialized = false;
    }

    public async Task<AuthResult> GetAuthorizationCodeAsync()
    {
        if (!IsInitialized)
            throw new InvalidOperationException("Not initialized");

        _state = Guid.NewGuid().ToString("N");
        string authorizeUrl =
            $"{AuthEndpoint}"
            + $"?client_id={_clientId}"
            + $"&redirect_uri={_redirectUri}"
            + $"&response_type=code"
            + $"&code_challenge={_codeChallenge}"
            + $"&code_challenge_method=S256"
            + $"&state={_state}"
            + $"&scope={Scope}";

        InfrastructureHelper.OpenBrowser(authorizeUrl);

        using var client = await _listener.AcceptTcpClientAsync();
        using var stream = client.GetStream();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        using var writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };

        if (await reader.ReadLineAsync() is not string requestLine)
            return AuthResult.Error("Could not read request");

        while (!string.IsNullOrEmpty(await reader.ReadLineAsync())) { }

        if (string.IsNullOrEmpty(requestLine))
            return AuthResult.Error("Empty request");

        string[] parts = requestLine.Split(' ');
        if (parts.Length < 2)
            return AuthResult.Error("Invalid request");

        string url = parts[1];
        if (!url.Contains("?"))
            return AuthResult.Error("No query parameters");

        string queryString = url.Substring(url.IndexOf('?') + 1);
        string? code = null;
        string? incomingState = null;

        foreach (var param in queryString.Split('&'))
        {
            var pair = param.Split('=');
            if (pair.Length == 2)
            {
                if (pair[0] == "code")
                    code = pair[1];
                if (pair[0] == "state")
                    incomingState = pair[1];
            }
        }

        string responseHtml =
            "<html>"
            + "<body style='font-family:sans-serif;'>"
            + "<h1>Authorization Successful</h1>"
            + "<p>You can close the browser window</p>"
            + "</body>"
            + "</html>";

        await writer.WriteAsync(
            "HTTP/1.1 200 OK\r\n"
                + "Content-Type: text/html\r\n"
                + "Connection: close\r\n\r\n"
                + responseHtml
        );

        if (incomingState != _state)
            return AuthResult.Error("State Mismatch");
        if (string.IsNullOrEmpty(code))
            return AuthResult.Error("Code not found");

        return new AuthResult { Code = code, IsError = false };
    }

    public async Task<AuthToken> ExchangeCodeForTokenAsync(AuthResult authResult)
    {
        if (!IsInitialized)
            throw new InvalidOperationException("Not initialized");

        if (authResult.IsError)
            return AuthToken.Error("Cannot obtain tokens from an erronous authorization result");

        var content = new FormUrlEncodedContent(
            new[]
            {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("client_id", _clientId),
                new KeyValuePair<string, string>("code", authResult.Code),
                new KeyValuePair<string, string>("redirect_uri", _redirectUri),
                new KeyValuePair<string, string>("code_verifier", _codeVerifier),
            }
        );

        return await CallTokenEndpointAsync(content);
    }

    public async Task<AuthToken> RefreshTokenAsync(string refreshToken)
    {
        if (!IsInitialized)
            throw new InvalidOperationException("Not initialized");

        if (string.IsNullOrEmpty(refreshToken))
            return AuthToken.Error("No refresh token");

        var content = new FormUrlEncodedContent(
            new[]
            {
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("client_id", _clientId),
                new KeyValuePair<string, string>("refresh_token", refreshToken),
            }
        );

        return await CallTokenEndpointAsync(content);
    }

    private static async Task<AuthToken> CallTokenEndpointAsync(FormUrlEncodedContent content)
    {
        using var client = new HttpClient();

        var response = await client.PostAsync(TokenEndpoint, content);
        string json = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            return AuthToken.Error("Failed to obtain tokens");

        if (JsonDocument.Parse(json) is not JsonDocument tokenData)
            return AuthToken.Error("Failed to parse the response");

        if (tokenData.RootElement.GetProperty("access_token").GetString() is not string accessToken)
            return AuthToken.Error("Failed to parse access token or expiration period");

        string refreshToken =
            tokenData.RootElement.GetProperty("refresh_token").GetString() ?? string.Empty;

        int expiresIn = 0;
        int refreshExpiresIn = 0;
        try
        {
            expiresIn = tokenData.RootElement.GetProperty("expires_in").GetInt32();
            refreshExpiresIn = tokenData
                .RootElement.GetProperty("refresh_token_expires_in")
                .GetInt32();
        }
        catch { }

        return new AuthToken()
        {
            AccessToken = accessToken,
            ExpiresAt = DateTime.Now.AddSeconds(expiresIn),
            RefreshToken = refreshToken,
            RefreshTokenExpiresAt = DateTime.Now.AddSeconds(refreshExpiresIn),
        };
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string GenerateCodeVerifier()
    {
        var rng = RandomNumberGenerator.Create();
        byte[] bytes = new byte[32];
        rng.GetBytes(bytes);
        return Base64UrlEncode(bytes);
    }

    private static string GenerateCodeChallenge(string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        return Base64UrlEncode(challengeBytes);
    }
}
