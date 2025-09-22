namespace SenseNetAuth.Models;

public class MultiFactorInfoResponse
{
    public bool MultiFactorEnabled { get; set; }
    public bool MultiFactorRegistered { get; set; }
    public string QrCodeSetupImageUrl { get; set; } = string.Empty;
    public string ManualEntryKey { get; set; } = string.Empty;
}
