namespace SenseNetAuth.Models.Options;

public class JwtSettings
{
	public string Issuer { get; set; } = string.Empty;
	public string Audience { get; set; } = string.Empty;
	public string SecretKey { get; set; } = string.Empty;
	public int TokenExpiryMinutes { get; set; }
	public int RefreshTokenExpiryDays { get; set; }
	public int AuthTokenExpiryMinutes { get; set; }
	public int MultiFactorAuthExpiryMinutes { get; set; }
}
