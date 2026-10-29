namespace SenseNetAuth.Models.ViewModels;

public class PasswordRecoveryViewModel : ExternalLoginFlow
{
    public string RepositoryUrl { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
    public string RecoveryToken { get; set; } = string.Empty;
}
