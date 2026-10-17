using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http;
using SecretManager.Server.Services;

namespace SecretManager.Server.Components.Shared;

/// <summary>
/// Base for interactive pages: resolves the user's access, knows the client IP, shows toasts and records
/// every UI action in the activity log.
/// </summary>
public abstract class AppPageBase : ComponentBase
{
    [Inject] protected AccessService AccessService { get; set; } = default!;
    [Inject] protected CircuitClientInfo ClientInfo { get; set; } = default!;
    [Inject] protected ActivityLogger Activity { get; set; } = default!;
    [Inject] protected EnvironmentRegistry Environments { get; set; } = default!;
    [Inject] protected NavigationManager Nav { get; set; } = default!;

    /// <summary>Available during static prerender only; used to capture the client IP before the circuit starts.</summary>
    [CascadingParameter] private HttpContext? HttpContext { get; set; }

    protected UserAccess Access { get; private set; } = UserAccess.Anonymous;
    protected string? Ip => ClientInfo.ClientIp;
    protected List<ToastMessage> Toasts { get; } = [];
    protected bool Busy { get; set; }

    protected override async Task OnInitializedAsync()
    {
        if (HttpContext is not null) ClientInfo.ClientIp ??= HttpContext.Connection.RemoteIpAddress?.ToString();
        Access = await AccessService.GetAsync();
        await OnPageInitializedAsync();
    }

    protected virtual Task OnPageInitializedAsync() => Task.CompletedTask;

    /// <summary>Records a UI action (button press, view) in the activity log.</summary>
    protected void LogAction(string action, string? target = null, string? environment = null, int status = 200, string? error = null) =>
        Activity.LogUi(Access.UserName, action, Nav.ToBaseRelativePath(Nav.Uri) is var p && p.Length > 0 ? "/" + p.Split('?')[0] : "/", target, environment, Ip, status, error);

    /// <summary>Runs an action with consistent error handling; validation/permission errors become toasts and are logged.</summary>
    protected async Task<bool> RunAsync(string action, Func<Task> work, string? success = null, string? target = null, string? environment = null)
    {
        Busy = true;
        try
        {
            await work();
            LogAction(action, target, environment);
            if (success is not null) Toast(success);
            return true;
        }
        catch (ValidationException ex)
        {
            LogAction(action, target, environment, 400, ex.Message);
            Toast(ex.Message, error: true);
        }
        catch (UnauthorizedAccessException ex)
        {
            LogAction(action, target, environment, 403, ex.Message);
            Toast(string.IsNullOrEmpty(ex.Message) ? "You are not allowed to do that." : ex.Message, error: true);
        }
        catch (KeyNotFoundException)
        {
            LogAction(action, target, environment, 404, "not found");
            Toast("That item no longer exists.", error: true);
        }
        finally
        {
            Busy = false;
        }
        return false;
    }

    protected void Toast(string message, bool error = false)
    {
        var t = new ToastMessage(message, error);
        Toasts.Add(t);
        StateHasChanged();
        _ = Task.Delay(error ? 6000 : 3500).ContinueWith(_ => InvokeAsync(() =>
        {
            Toasts.Remove(t);
            StateHasChanged();
        }));
    }

    protected static string Ago(DateTime? utc)
    {
        if (utc is null) return "never";
        var d = DateTime.UtcNow - DateTime.SpecifyKind(utc.Value, DateTimeKind.Utc);
        return d.TotalSeconds < 60 ? "just now"
            : d.TotalMinutes < 60 ? $"{(int)d.TotalMinutes}m ago"
            : d.TotalHours < 24 ? $"{(int)d.TotalHours}h ago"
            : d.TotalDays < 30 ? $"{(int)d.TotalDays}d ago"
            : utc.Value.ToString("yyyy-MM-dd");
    }
}

public sealed record ToastMessage(string Text, bool Error);
