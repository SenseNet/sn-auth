namespace SenseNetAuth.Models;

public class ForgottenPasswordRequest
{
    public string Email { get; set; } = string.Empty;
    public string PasswordRecoveryUrl {  get; set; } = string.Empty;
}
