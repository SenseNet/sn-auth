namespace SenseNetAuth.Models;

public class TokenRequest
{
	public string Token { get; set; } = string.Empty;
    public string? CodeVerifier { get; set; }
}
