using Microsoft.Extensions.Options;
using SenseNetAuth.Models.Options;

namespace SenseNetAuth.TokenProviders.InMemory;

public class AuthTokenProvider : InMemoryTokenProvider
{
    private readonly JwtSettings _jwtSettings;

    public AuthTokenProvider(IOptions<JwtSettings> options)
    {
        _jwtSettings = options.Value;
    }

    public override string CreateToken(int userId, string siteUrl)
        => CreateToken(new UserInfo(userId, default, siteUrl));

    public override string CreateToken(UserInfo userInfo)
    {
        var expiration = DateTimeOffset.UtcNow.AddMinutes(_jwtSettings.AuthTokenExpiryMinutes);
        var token = GenerateUniqueToken(128);

        StoreToken(token, userInfo with { Expiry = expiration }, _jwtSettings.SingleSessionPerUser);

        return token;
    }
}
