namespace SenseNetAuth.Models.ViewModels;

public class PasswordRecoveryViewModel
{
    public string RedirectUrl { get; set; } = string.Empty;
    public string CallbackUri { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
    public string RecoveryToken { get; set; } = string.Empty;
}
