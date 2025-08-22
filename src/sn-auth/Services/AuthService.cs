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
                userId = _rememberMeTokenProvider.GetUserInfoByToken(loginRequest.RememberMeToken)!.Value.UserId;
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
                RememberMeToken = _rememberMeTokenProvider.CreateToken(userId, loginRequest.SiteUrl),
                FullName = user.FullName,
                LoginName = user.LoginName
            };
        }

        var multiFactorInfo = await _userService.GetMultiFactorAuthenticationInfoAsync(userId, cancel);
        if (multiFactorInfo == null || !multiFactorInfo.MultiFactorEnabled)
        {
            response.AccessToken = _accessTokenProvider.CreateToken(userId, loginRequest.SiteUrl);
            response.RefreshToken = _refreshTokenProvider.CreateToken(userId, loginRequest.SiteUrl);

            return response;
        }
        else
        {
            response.MultiFactorRequired = true;
            response.MultiFactorAuthToken = _multiFactorAuthTokenProvider.CreateToken(userId, loginRequest.SiteUrl);

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
        var userInfo = _multiFactorAuthTokenProvider.GetUserInfoByToken(loginRequest.MultiFactorAuthToken);
        if (!userInfo.HasValue || !_multiFactorAuthTokenProvider.IsTokenValid(loginRequest.MultiFactorAuthToken))
            throw new BadRequestException(ResponseMessages.InvalidMultiFactorToken);

        if (!await _userService.ValidateTwoFactorCodeAsync(userInfo.Value.UserId, loginRequest.MultiFactorCode, cancel))
            throw new BadRequestException(ResponseMessages.InvalidMultiFactorCode);

        if (directLogin)
        {
            return new LoginResponse
            {
                AccessToken = _accessTokenProvider.CreateToken(userInfo.Value.UserId, loginRequest.SiteUrl),
                RefreshToken = _refreshTokenProvider.CreateToken(userInfo.Value.UserId, loginRequest.SiteUrl)
            };
        }
        else
        {
            return new LoginResponse
            {
                AuthToken = _authTokenProvider.CreateToken(userInfo.Value.UserId, loginRequest.SiteUrl)
            };
        }
    }

    public void Logout(string token)
    {
        var userInfo = _accessTokenProvider.GetUserInfoByToken(token);
        if (userInfo.HasValue)
        {
            _accessTokenProvider.InvalidateToken(userInfo.Value);
            _refreshTokenProvider.InvalidateToken(userInfo.Value);
        }
    }

    public bool ValidateToken(string token)
    {
        return _accessTokenProvider.IsTokenValid(token);
    }

    public LoginResponse RefreshToken(string token)
    {
        var userInfo = _refreshTokenProvider.GetValidUserInfo(token);
        if (userInfo.HasValue)
        {
            return new LoginResponse
            {
                AccessToken = _accessTokenProvider.CreateToken(userInfo.Value),
                RefreshToken = _refreshTokenProvider.CreateToken(userInfo.Value)
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
            var token = _passwordRecoveryTokenProvider.CreateToken(user.Id, "");
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

        var userInfo = _passwordRecoveryTokenProvider.GetUserInfoByToken(passwordRecoveryRequest.Token);
        if (await _userService.ChangePasswordAsync(userInfo.Value.UserId, passwordRecoveryRequest.Password, cancel))
        {
            _passwordRecoveryTokenProvider.InvalidateToken(passwordRecoveryRequest.Token);
            _rememberMeTokenProvider.InvalidateToken(userInfo.Value);
        }

    }

    public async Task<LoginResponse> AuthenticateAsync(LoginRequest loginRequest, CancellationToken cancel)
    {
        int userId;
        if (!string.IsNullOrEmpty(loginRequest.RememberMeToken))
        {
            var userInfo = _rememberMeTokenProvider.GetValidUserInfo(loginRequest.RememberMeToken);
            if (userInfo.HasValue)
                userId = userInfo.Value.UserId;
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
            AuthToken = _authTokenProvider.CreateToken(userId, loginRequest.SiteUrl),
        };

        if (loginRequest.RememberMeRequested && string.IsNullOrEmpty(loginRequest.RememberMeToken))
        {
            var user = await _userService.GetUserByUserIdAsync(userId, cancel).ConfigureAwait(false);
            response.RememberMeDetails = new RememberMeDetails
            {
                RememberMeToken = _rememberMeTokenProvider.CreateToken(userId, loginRequest.SiteUrl),
                FullName = user.FullName,
                LoginName = user.LoginName
            };
        }

        if (multiFactorInfo != null && multiFactorInfo.MultiFactorEnabled)
        {
            response.MultiFactorRequired = true;
            response.MultiFactorAuthToken = _multiFactorAuthTokenProvider.CreateToken(userId, loginRequest.SiteUrl);

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

        var userInfo = _authTokenProvider.GetUserInfoByToken(tokenRequest.Token);

        return new LoginResponse
        {
            AccessToken = _accessTokenProvider.CreateToken(userInfo.Value.UserId, userInfo.Value.SiteUrl),
            RefreshToken = _refreshTokenProvider.CreateToken(userInfo.Value.UserId, userInfo.Value.SiteUrl)
        };
    }

    public async Task ChangePasswordAsync(string bearerToken, ChangePasswordRequest changePasswordRequest, CancellationToken cancel)
    {
        var userInfo = _accessTokenProvider.GetValidUserInfo(bearerToken);
        if (userInfo is null)
            throw new UnauthorizedException(ResponseMessages.InvalidAccessToken);

        await _userService.ChangePasswordAsync(userInfo.Value.UserId, changePasswordRequest.Password, cancel);
        _rememberMeTokenProvider.InvalidateToken(userInfo.Value);
    }

    public async Task<UserDetails> GetUserDetailsAsync(string token, CancellationToken cancel)
    {
        var userInfo = _accessTokenProvider.GetValidUserInfo(token);

        if (userInfo is null)
            throw new UnauthorizedException(ResponseMessages.InvalidAccessToken);

        var user = await _userService.GetUserByUserIdAsync(userInfo.Value.UserId, cancel);

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
