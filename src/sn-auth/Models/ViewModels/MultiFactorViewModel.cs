namespace SenseNetAuth.Models.ViewModels;

public class MultiFactorViewModel : ExternalLoginFlow
{
    public string RepositoryUrl { get; set; } = string.Empty;
    public bool MultiFactorRequired { get; set; }
    public string QrCodeSetupImageUrl { get; set; } = string.Empty;
    public string ManualEntryKey { get; set; } = string.Empty;
    public string MultiFactorAuthToken { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;

}
