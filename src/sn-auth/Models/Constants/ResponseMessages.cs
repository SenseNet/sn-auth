namespace SenseNetAuth.Models.Constants;

public class ResponseMessages
{
    // Login, token validation
    public const string InvalidCredentials = "INVALID_CREDENTIALS";
    public const string InvalidApiKey = "INVALID_API_KEY";
    public const string Unauthorized = "UNAUTHORIZED";
    public const string InvalidAuthToken = "INVALID_AUTH_TOKEN";
    public const string InvalidAccessToken = "INVALID_ACCESS_TOKEN";
    public const string InvalidMultiFactorCode = "INVALID_MULTI_FACTOR_CODE";
    public const string InvalidMultiFactorToken = "INVALID_MULTI_FACTOR_TOKEN";
    public const string RememberMeTokenExpired = "REMEMBER_ME_TOKEN_EXPIRED";

    // Server errors
    public const string InternalServerError = "INTERNAL_SERVER_ERROR";

    //Registration
    public const string RegistationDisabled = "REGISTRATION_DISABLED";
    public const string InvalidEmail = "INVALID_EMAIL";
    public const string InvalidPassword = "INVALID_PASSWORD";
    public const string UserAlreadyExist = "USER_ALREADY_EXIST";

    //PasswordRecovery
    public const string InvalidRecoveryToken = "INVALID_RECOVERY_TOKEN";
}
