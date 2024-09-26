namespace SenseNetAuth.Models.ViewModels;

public class MultiFactorViewModel
{
    public string RedirectUrl { get; set; } = string.Empty;
    public string CallbackUri { get; set; } = string.Empty;
    public bool MultiFactorRequired { get; set; }
    public string QrCodeSetupImageUrl { get; set; } = string.Empty;
    public string ManualEntryKey { get; set; } = string.Empty;
    public string MultiFactorAuthToken { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;

}
