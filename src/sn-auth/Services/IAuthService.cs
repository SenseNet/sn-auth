using SenseNetAuth.Models;

namespace SenseNetAuth.Services;

public interface IAuthService
{
	public Task<LoginResponse> LoginAsync(LoginRequest loginRequest, CancellationToken cancel);
	public bool ValidateToken(string token);
	public void Logout(string token);
	public LoginResponse RefreshToken(string token);
	public Task<RegistrationResponse> RegisterAsync(RegistrationRequest registrationRequest, CancellationToken cancel);
	public Task ForgottenPasswordAsync(ForgottenPasswordRequest forgottenPasswordRequest, CancellationToken cancel);
    public Task ForgottenPasswordAsync(ForgottenPasswordRequest forgottenPasswordRequest, string callbackUri, CancellationToken cancel);
    public Task PasswordRecoveryAsync(PasswordRecoveryRequest passwordRecoveryRequest, CancellationToken cancel);
	public Task<LoginResponse> AuthenticateAsync(LoginRequest loginRequest, CancellationToken cancel);
    public LoginResponse ConvertAuthToken(TokenRequest tokenRequest);
    public Task ChangePasswordAsync(string bearerToken, ChangePasswordRequest changePasswordRequest, CancellationToken cancel);
	public Task<LoginResponse> MultiFactorLoginAsync(MultiFactorLoginRequest loginRequest, CancellationToken cancel, bool directLogin = true);
	public void DeleteRememberMeToken(string token);
	public Task<UserDetails> GetUserDetailsAsync(string token, CancellationToken cancel);
}
