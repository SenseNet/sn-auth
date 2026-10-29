using Microsoft.AspNetCore.WebUtilities;
using SenseNetAuth.Models;

namespace SenseNetAuth.Models.ViewModels;

public class ExternalLoginFlow
{
    public string RedirectUrl { get; set; } = string.Empty;
    public string CallbackUri { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public string CodeChallenge { get; set; } = string.Empty;
    public string CodeChallengeMethod { get; set; } = string.Empty;

    public string QueryString => Microsoft.AspNetCore.Http.QueryString.Create(new Dictionary<string, string?>
    {
        ["redirectUrl"] = RedirectUrl, ["callbackUri"] = CallbackUri,
        ["state"] = State, ["codeChallenge"] = CodeChallenge, ["codeChallengeMethod"] = CodeChallengeMethod
    }).ToString();

    public static ExternalLoginFlow FromForm(IFormCollection form) => new()
    {
        RedirectUrl = form["RedirectUrl"].ToString(), CallbackUri = form["CallbackUri"].ToString(),
        State = form["State"].ToString(), CodeChallenge = form["CodeChallenge"].ToString(),
        CodeChallengeMethod = form["CodeChallengeMethod"].ToString()
    };

    public T CopyTo<T>(T model) where T : ExternalLoginFlow
    {
        model.RedirectUrl = RedirectUrl;
        model.CallbackUri = CallbackUri;
        model.State = State;
        model.CodeChallenge = CodeChallenge;
        model.CodeChallengeMethod = CodeChallengeMethod;
        return model;
    }

    public bool IsValid(IEnumerable<string> allowedHosts)
    {
        if (!allowedHosts.Contains(RedirectUrl) || !TryCallback(CallbackUri, out _))
            return false;
        try { _ = AuthorizationCodeBinding.Create(State, CodeChallenge, CodeChallengeMethod, CallbackUri); }
        catch { return false; }
        return true;
    }

    private bool TryCallback(string callbackUri, out Uri? callback)
    {
        callback = null;
        return Uri.TryCreate(RedirectUrl, UriKind.Absolute, out var site) &&
            (site.Scheme == "https" || site.Scheme == "http") &&
            Uri.TryCreate(site, callbackUri, out callback) &&
            callback.Scheme == site.Scheme && callback.Host == site.Host && callback.Port == site.Port &&
            string.IsNullOrEmpty(callback.UserInfo);
    }

    public string CallbackUrl(LoginResponse response)
    {
        // Bound MFA responses carry the callback that was validated before password authentication.
        if (!TryCallback(response.CallbackUri ?? CallbackUri, out var callback))
            throw new InvalidOperationException("Invalid login callback");
        var query = new Dictionary<string, string?> { ["auth_code"] = response.AuthToken };
        if (!string.IsNullOrEmpty(response.State)) query["state"] = response.State;
        return QueryHelpers.AddQueryString(callback!.AbsoluteUri, query);
    }
}
