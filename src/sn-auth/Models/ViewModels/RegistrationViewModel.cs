namespace SenseNetAuth.Models.ViewModels;

public class RegistrationViewModel
{
    public string RepositoryUrl { get; set; } = string.Empty;
    public string RedirectUrl { get; set; } = string.Empty;
    public string CallbackUri { get; set; } = string.Empty;
    public bool IsRegistrationEnabled { get; set; }
    public bool IsHostInvalid { get; set; }
    public string ErrorMessage { get; set; } = string.Empty;
    public string SuccessMessage { get; set; } = string.Empty;
}
