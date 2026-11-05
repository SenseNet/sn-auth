namespace SenseNetAuth.Models;

public class LoginRequest
{
    public string LoginName { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string RememberMeToken { get; set; } = string.Empty;
    public bool RememberMeRequested { get; set; }
    public required string SiteUrl { get; set; }
    public string State { get; set; } = string.Empty;
    public string CodeChallenge { get; set; } = string.Empty;
    public string CodeChallengeMethod { get; set; } = string.Empty;
    public string CallbackUri { get; set; } = string.Empty;
}
