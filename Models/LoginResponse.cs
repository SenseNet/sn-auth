namespace SenseNetAuth.Models;

public class LoginResponse
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public string AuthToken { get; set; } = string.Empty;
    public bool MultiFactorRequired { get; set; }
    public string QrCodeSetupImageUrl { get; set; } = string.Empty;
    public string ManualEntryKey { get; set; } = string.Empty;
    public string MultiFactorAuthToken { get; set; } = string.Empty;
    public RememberMeDetails? RememberMeDetails { get; set; }
}
