using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using SenseNetAuth.Infrastructure.Exceptions;
using SenseNetAuth.Models;
using SenseNetAuth.Models.Constants;
using SenseNetAuth.Models.Options;
using SenseNetAuth.TokenProviders;
using SenseNetAuth.TokenProviders.InMemory;

namespace SenseNetAuth.Services;

public class AuthService : IAuthService
{
    private const string EMAIL_REGEX = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";

    private readonly IUserService _userService;
    private readonly ITokenProvider _accessTokenProvider;
    private readonly ITokenProvider _refreshTokenProvider;
    private readonly ITokenProvider _authTokenProvider;
    private readonly ITokenProvider _passwordRecoveryTokenProvider;
    private readonly ITokenProvider _multiFactorAuthTokenProvider;
    private readonly ITokenProvider _rememberMeTokenProvider;
    private readonly RegistrationSettings _registrationSettings;
    private readonly ApplicationSettings _applicationSettings;
    private readonly IEmailService _emailService;

    public AuthService(
        IUserService userService,
        IOptions<JwtSettings> jwtOptions,
        IOptions<RegistrationSettings> registrationOptions,
        IOptions<PasswordRecoverySettings> recoveryOptions,
        IOptions<ApplicationSettings> applicationOptions,
        IEmailService emailService)
    {
        _userService = userService;
        _accessTokenProvider = new JwtTokenProvider(jwtOptions);
        _refreshTokenProvider = new RefreshTokenProvider(jwtOptions);
        _authTokenProvider = new AuthTokenProvider(jwtOptions);
        _multiFactorAuthTokenProvider = new MultiFactorAuthTokenProvider(jwtOptions);
        _passwordRecoveryTokenProvider = new PasswordRecoveryTokenProvider(recoveryOptions);
        _rememberMeTokenProvider = new RememberMeTokenProvider();

        _applicationSettings = applicationOptions.Value;
        _registrationSettings = registrationOptions.Value;
        _emailService = emailService;
    }

    public async Task<LoginResponse> LoginAsync(LoginRequest loginRequest, CancellationToken cancel)
    {
        int userId;
        if (!string.IsNullOrEmpty(loginRequest.RememberMeToken))
        {
            if (_rememberMeTokenProvider.IsTokenValid(loginRequest.RememberMeToken))
                userId = _rememberMeTokenProvider.GetUserIdByToken(loginRequest.RememberMeToken)!.Value;
            else
                throw new BadRequestException(ResponseMessages.RememberMeTokenExpired);
        }
        else
        {
            userId = (await _userService.ValidateCredentialsAsync(loginRequest.LoginName, loginRequest.Password, cancel)
                        .ConfigureAwait(false))
                    ?? throw new BadRequestException(ResponseMessages.InvalidCredentials);
        }

        var response = new LoginResponse();
        if (loginRequest.RememberMeRequested && !string.IsNullOrEmpty(loginRequest.RememberMeToken)) 
        {
            var user = await _userService.GetUserByUserIdAsync(userId, cancel).ConfigureAwait(false);
            response.RememberMeDetails = new RememberMeDetails
            {
                RememberMeToken = _rememberMeTokenProvider.CreateToken(userId),
                FullName = user.FullName,
                LoginName = user.LoginName
            };
        }

        var multiFactorInfo = await _userService.GetMultiFactorAuthenticationInfoAsync(userId, cancel);
        if (multiFactorInfo == null || !multiFactorInfo.MultiFactorEnabled)
        {
            response.AccessToken = _accessTokenProvider.CreateToken(userId);
            response.RefreshToken = _refreshTokenProvider.CreateToken(userId);

            return response;
        }
        else
        {
            response.MultiFactorRequired = true;
            response.MultiFactorAuthToken = _multiFactorAuthTokenProvider.CreateToken(userId);

            if (!multiFactorInfo.MultiFactorRegistered)
            {
                response.QrCodeSetupImageUrl = multiFactorInfo.QrCodeSetupImageUrl;
                response.ManualEntryKey = multiFactorInfo.ManualEntryKey;
            }

            return response;
        }
    }

    public async Task<LoginResponse> MultiFactorLoginAsync(MultiFactorLoginRequest loginRequest, CancellationToken cancel, bool directLogin = true)
    {
        var userId = _multiFactorAuthTokenProvider.GetUserIdByToken(loginRequest.MultiFactorAuthToken);
        if (!userId.HasValue || !_multiFactorAuthTokenProvider.IsTokenValid(loginRequest.MultiFactorAuthToken))
            throw new BadRequestException(ResponseMessages.InvalidMultiFactorToken);

        if (!await _userService.ValidateTwoFactorCodeAsync(userId.Value, loginRequest.MultiFactorCode, cancel))
            throw new BadRequestException(ResponseMessages.InvalidMultiFactorCode);

        if (directLogin)
        {
            return new LoginResponse
            {
                AccessToken = _accessTokenProvider.CreateToken(userId.Value),
                RefreshToken = _refreshTokenProvider.CreateToken(userId.Value)
            };
        }
        else
        {
            return new LoginResponse
            {
                AuthToken = _authTokenProvider.CreateToken(userId.Value)
            };
        }
    }

    public void Logout(string token)
    {
        var userId = _accessTokenProvider.GetUserIdByToken(token);
        if (userId.HasValue)
        {
            _accessTokenProvider.InvalidateToken(userId.Value);
            _refreshTokenProvider.InvalidateToken(userId.Value);
        }
    }

    public bool ValidateToken(string token)
    {
        return _accessTokenProvider.IsTokenValid(token);
    }

    public LoginResponse RefreshToken(string token)
    {
        if (_refreshTokenProvider.IsTokenValid(token))
        {
            var userId = _refreshTokenProvider.GetUserIdByToken(token);
            return new LoginResponse
            {
                AccessToken = _accessTokenProvider.CreateToken(userId!.Value),
                RefreshToken = _refreshTokenProvider.CreateToken(userId!.Value)
            };
        }

        throw new UnauthorizedException(ResponseMessages.Unauthorized);
    }

    public async Task<RegistrationResponse> RegisterAsync(RegistrationRequest registrationRequest, CancellationToken cancel)
    {
        if (!_registrationSettings.IsEnabled)
            throw new BadRequestException(ResponseMessages.RegistationDisabled);
        if (!ValidateEmail(registrationRequest.Email))
            throw new BadRequestException(ResponseMessages.InvalidEmail);
        if (!ValidatePassword(registrationRequest.Password))
            throw new BadRequestException(ResponseMessages.InvalidPassword);

        var user = await _userService.RegisterUserAsync(registrationRequest.Email, registrationRequest.Password, registrationRequest.FullName, cancel)
            .ConfigureAwait(false);
        if (user != null)
        {
            return new RegistrationResponse
            {
                Email = user.Email ?? registrationRequest.Email,
                LoginName = user.LoginName ?? string.Empty
            };
        }
        else
        {
            throw new BadRequestException(ResponseMessages.UserAlreadyExist);
        }
    }

    public async Task ForgottenPasswordAsync(ForgottenPasswordRequest forgottenPasswordRequest, CancellationToken cancel)
    {
        await ForgottenPasswordAsync(forgottenPasswordRequest, string.Empty, cancel);
    }

    public async Task ForgottenPasswordAsync(ForgottenPasswordRequest forgottenPasswordRequest, string callbackUri, CancellationToken cancel)
    {
        if (string.IsNullOrEmpty(forgottenPasswordRequest.Email))
            throw new BadRequestException(ResponseMessages.InvalidEmail);

        var user = await _userService.GetUserByEmailAsync(forgottenPasswordRequest.Email, cancel)
            .ConfigureAwait(false);
        if (user != null)
        {
            var token = _passwordRecoveryTokenProvider.CreateToken(user.Id);
            var passwordRecoveryUrl = !string.IsNullOrEmpty(forgottenPasswordRequest.PasswordRecoveryUrl)
                ? forgottenPasswordRequest.PasswordRecoveryUrl
                : $"{_applicationSettings.Url}/PasswordRecovery";

            var emailBody = _emailService.GenerateEmailBody("ForgottenPassword.html", new Dictionary<string, string>
            {
                { "link", $"{passwordRecoveryUrl}?token={token}{(!string.IsNullOrEmpty(callbackUri) ? $"&{callbackUri}" : "")}" }
            });
            _emailService.SendEmail(user.Email!, "Password recovery", emailBody);
        }
    }

    public async Task PasswordRecoveryAsync(PasswordRecoveryRequest passwordRecoveryRequest, CancellationToken cancel)
    {
        if (!_passwordRecoveryTokenProvider.IsTokenValid(passwordRecoveryRequest.Token))
            throw new BadRequestException(ResponseMessages.InvalidRecoveryToken);

        var userId = _passwordRecoveryTokenProvider.GetUserIdByToken(passwordRecoveryRequest.Token);
        if (await _userService.ChangePasswordAsync(userId!.Value, passwordRecoveryRequest.Password, cancel))
        {
            _passwordRecoveryTokenProvider.InvalidateToken(passwordRecoveryRequest.Token);
            _rememberMeTokenProvider.InvalidateToken(userId.Value);
        }
            
    }

    public async Task<LoginResponse> AuthenticateAsync(LoginRequest loginRequest, CancellationToken cancel)
    {
        int userId;
        if (!string.IsNullOrEmpty(loginRequest.RememberMeToken))
        {
            if (_rememberMeTokenProvider.IsTokenValid(loginRequest.RememberMeToken))
                userId = _rememberMeTokenProvider.GetUserIdByToken(loginRequest.RememberMeToken)!.Value;
            else
                throw new BadRequestException(ResponseMessages.RememberMeTokenExpired);
        }
        else
        {
            userId = (await _userService.ValidateCredentialsAsync(loginRequest.LoginName, loginRequest.Password, cancel)
                        .ConfigureAwait(false))
                    ?? throw new BadRequestException(ResponseMessages.InvalidCredentials);
        }

        var multiFactorInfo = await _userService.GetMultiFactorAuthenticationInfoAsync(userId, cancel);

        var response = new LoginResponse
        {
            AuthToken = _authTokenProvider.CreateToken(userId),
        };

        if (loginRequest.RememberMeRequested && string.IsNullOrEmpty(loginRequest.RememberMeToken))
        {
            var user = await _userService.GetUserByUserIdAsync(userId, cancel).ConfigureAwait(false);
            response.RememberMeDetails = new RememberMeDetails
            {
                RememberMeToken = _rememberMeTokenProvider.CreateToken(userId),
                FullName = user.FullName,
                LoginName = user.LoginName
            };
        }

        if (multiFactorInfo != null && multiFactorInfo.MultiFactorEnabled)
        {
            response.MultiFactorRequired = true;
            response.MultiFactorAuthToken = _multiFactorAuthTokenProvider.CreateToken(userId);

            if (!multiFactorInfo.MultiFactorRegistered)
            {
                response.QrCodeSetupImageUrl = multiFactorInfo.QrCodeSetupImageUrl;
                response.ManualEntryKey = multiFactorInfo.ManualEntryKey;
            }
        }

        return response;
    }

    public LoginResponse ConvertAuthToken(TokenRequest tokenRequest)
    {
        if (!_authTokenProvider.IsTokenValid(tokenRequest.Token))
            throw new UnauthorizedException(ResponseMessages.InvalidAuthToken);

        var userId = _authTokenProvider.GetUserIdByToken(tokenRequest.Token);

        return new LoginResponse
        {
            AccessToken = _accessTokenProvider.CreateToken(userId!.Value),
            RefreshToken = _refreshTokenProvider.CreateToken(userId!.Value)
        };
    }

    public async Task ChangePasswordAsync(string bearerToken, ChangePasswordRequest changePasswordRequest, CancellationToken cancel)
    {
        if (!_accessTokenProvider.IsTokenValid(bearerToken))
            throw new UnauthorizedException(ResponseMessages.InvalidAccessToken);

        var userId = _accessTokenProvider.GetUserIdByToken(bearerToken);
        await _userService.ChangePasswordAsync(userId!.Value, changePasswordRequest.Password, cancel);
        _rememberMeTokenProvider.InvalidateToken(userId.Value);
    }

    public async Task<UserDetails> GetUserDetailsAsync(string token, CancellationToken cancel)
    {
        var userId = _accessTokenProvider.GetUserIdByToken(token);

        if (!_accessTokenProvider.IsTokenValid(token))
            throw new UnauthorizedException(ResponseMessages.InvalidAccessToken);

        var user = await _userService.GetUserByUserIdAsync(userId.Value, cancel);

        return new UserDetails
        {
            Id = user.Id,
            DisplayName = user.DisplayName,
            Email = user.Email,
            FullName = user.FullName,
            LoginName = user.LoginName,
            Name = user.Name,
            Path = user.Path,
            Avatar = new Avatar
            {
                Url = user.Avatar?.Url
            }
        };
    }

    public void DeleteRememberMeToken(string token)
    {
        _rememberMeTokenProvider.InvalidateToken(token);
    }

    private bool ValidateEmail(string email) => !string.IsNullOrEmpty(email)
            && Regex.IsMatch(email, EMAIL_REGEX);

    private bool ValidatePassword(string password) => !string.IsNullOrEmpty(password)
            && password.Length >= 8
            && password.Any(char.IsDigit)
            && password.Any(char.IsLower)
            && password.Any(char.IsUpper);
}
