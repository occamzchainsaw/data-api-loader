using System.Diagnostics;

namespace DataApiLoader;

public static class InfrastructureHelper
{
    public static void OpenBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch
        {
            if (
                System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
                    System.Runtime.InteropServices.OSPlatform.Windows
                )
            )
                Process.Start(
                    new ProcessStartInfo("cmd", $"/c start {url.Replace("&", "^&")}")
                    {
                        CreateNoWindow = true,
                    }
                );
            else if (
                System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
                    System.Runtime.InteropServices.OSPlatform.Linux
                )
            )
                Process.Start("xdg-open", url);
            else if (
                System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
                    System.Runtime.InteropServices.OSPlatform.OSX
                )
            )
                Process.Start("open", url);
            else
                Console.WriteLine($"Please open this URL manually: {url}");
        }
    }
}
