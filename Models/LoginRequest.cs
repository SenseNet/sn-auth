namespace SenseNetAuth.Models;

public class LoginRequest
{
	public string LoginName { get; set; } = string.Empty;
	public string Password { get; set; } = string.Empty;
	public string RememberMeToken { get; set; } = string.Empty;
	public bool RememberMeRequested { get; set; }
}
