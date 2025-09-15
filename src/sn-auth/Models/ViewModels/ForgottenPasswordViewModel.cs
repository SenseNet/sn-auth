namespace SenseNetAuth.Models.ViewModels;

public class ForgottenPasswordViewModel
{
    public string RedirectUrl { get; set; } = string.Empty;
    public string CallbackUri { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
    public string SuccessMessage { get; set; } = string.Empty;
}
