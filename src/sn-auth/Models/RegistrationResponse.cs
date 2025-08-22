namespace SenseNetAuth.Models;

public class RegistrationResponse
{
    public string Email { get; set; } = string.Empty;
    public string LoginName { get; set; } = string.Empty;
    public bool MultiFactorRequired { get; set; }
    public string QrCodeSetupImageUrl { get; set; } = string.Empty;
    public string ManualEntryKey { get; set; } = string.Empty;
    public string MultiFactorAuthToken { get; set; } = string.Empty;
}
