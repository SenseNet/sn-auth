namespace SenseNetAuth.Models.ViewModels;

public class ForgottenPasswordViewModel : ExternalLoginFlow
{
    public string RepositoryUrl { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
    public string SuccessMessage { get; set; } = string.Empty;
}
