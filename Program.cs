using System.Collections.Concurrent;
using DataApiLoader;
using Spectre.Console;

// See https://aka.ms/new-console-template for more information
Layout layout = new Layout("Root").SplitColumns(
    new Layout("Menu").Ratio(1),
    new Layout("Output").Ratio(3)
);

// todo change to own type which implements a rolling list of N messages
List<string> outputLog = [];
ConcurrentQueue<string> messageQueue = new();
bool isAuthorizing = false;

Panel GetOutputPanel()
{
    string text = string.Join("\n", outputLog.TakeLast(20));
    return new Panel(text)
        .Header("Output")
        .BorderColor(isAuthorizing ? Color.Yellow : Color.Gray)
        .Expand(); // fill available space
}

Panel GetMenuPanel()
{
    string menuText =
        "[bold]Controls:[/]\n"
        + "[DeepSkyBlue2]A[/] Authorize\n"
        + "[DeepSkyBlue2]R[/] Refresh Token\n"
        + "[DeepSkyBlue2]C[/] Clear Output\n"
        + "[DeepSkyBlue2]Q[/] Quit";

    return new Panel(menuText).Header("Menu").BorderColor(Color.Gray).Expand();
}

layout["Menu"].Update(GetMenuPanel());
layout["Output"].Update(GetOutputPanel());

AuthClient authClient = new();
authClient.Initialize("cartrack-agg", "/oauth/redirect");
AuthToken token = new();

await AnsiConsole
    .Live(layout)
    .Start(async ctx =>
    {
        bool isRunning = true;
        while (isRunning)
        {
            if (Console.KeyAvailable)
            {
                var key = Console.ReadKey(intercept: true).Key;
                switch (key)
                {
                    case ConsoleKey.A:
                        if (!isAuthorizing)
                            StartAuthProcess();
                        break;
                    case ConsoleKey.R:
                        RefreshToken();
                        break;
                    case ConsoleKey.Q:
                        isRunning = false;
                        break;
                    default:
                        break;
                }
            }

            while (messageQueue.TryDequeue(out var msg))
            {
                outputLog.Add(msg);
                while (outputLog.Count > 20)
                    outputLog.RemoveAt(0);
            }

            layout["Menu"].Update(GetMenuPanel());
            layout["Output"].Update(GetOutputPanel());

            ctx.Refresh();

            Thread.Sleep(50);
        }
    });

void StartAuthProcess()
{
    isAuthorizing = true;
    messageQueue.Enqueue("[yellow]Opening browser for auth...[/]");

    Task.Run(async () =>
    {
        try
        {
            var authResult = await authClient.GetAuthorizationCodeAsync();
            if (authResult.IsError)
            {
                messageQueue.Enqueue($"[red bold]Error:[/] {authResult.ErrorMessage}");
                return;
            }

            messageQueue.Enqueue(
                $"[green bold]Authorization Code:[/] {authResult.Code[..10]}(...)"
            );

            token = await authClient.ExchangeCodeForTokenAsync(authResult);
            if (token.IsError)
            {
                messageQueue.Enqueue($"[red bold]Error:[/] {token.ErrorMessage}");
                return;
            }

            messageQueue.Enqueue($"[green bold]Access token obtained![/]");
            messageQueue.Enqueue($"[bold]Token:[/] {token.AccessToken[..10]}(...)");
            messageQueue.Enqueue($"[bold]Expires:[/] {token.ExpiresAt:HH:mm:ss}");
            messageQueue.Enqueue($"[bold]Refresh Token:[/] {token.RefreshToken[..10]}(...)");
            messageQueue.Enqueue($"[bold]Expires:[/] {token.RefreshTokenExpiresAt:HH:mm:ss}");
        }
        catch
        {
            messageQueue.Enqueue($"[red bold]Auth Failed[/]");
        }
        finally
        {
            isAuthorizing = false;
        }
    });
}

void RefreshToken()
{
    /*if (token.RefreshTokenExpiresAt >= DateTime.Now)
    {
        messageQueue.Enqueue(
            $"[red bold]Refresh Token Expired![/] Was valid until: {token.RefreshTokenExpiresAt:HH:mm:ss}"
        );
        return;
    }*/

    messageQueue.Enqueue("[yellow]Attempting to refresh the token...[/]");

    Task.Run(async () =>
    {
        try
        {
            token = await authClient.RefreshTokenAsync(token.RefreshToken);
            if (token.IsError)
            {
                messageQueue.Enqueue(($"[red bold]Error:[/] {token.ErrorMessage}"));
                return;
            }

            messageQueue.Enqueue($"[green bold]Access token obtained![/]");
            messageQueue.Enqueue($"[bold]Token:[/] {token.AccessToken[..10]}(...)");
            messageQueue.Enqueue($"[bold]Expires:[/] {token.ExpiresAt:HH:mm:ss}");
            messageQueue.Enqueue($"[bold]Refresh Token:[/] {token.RefreshToken[..10]}(...)");
            messageQueue.Enqueue($"[bold]Expires:[/] {token.RefreshTokenExpiresAt:HH:mm:ss}");
        }
        catch
        {
            messageQueue.Enqueue($"[red bold]Auth Failed[/]");
        }
        finally
        {
            isAuthorizing = false;
        }
    });
}
