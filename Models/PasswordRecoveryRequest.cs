namespace SenseNetAuth.Models;

public class PasswordRecoveryRequest
{
    public string Token { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}
