using Microsoft.Extensions.Options;
using SenseNetAuth.Models.Options;

namespace SenseNetAuth.TokenProviders.InMemory;

public class MultiFactorAuthTokenProvider : InMemoryTokenProvider
{
    private readonly JwtSettings _jwtSettings;

    public MultiFactorAuthTokenProvider(IOptions<JwtSettings> jwtSettings)
    {
        _jwtSettings = jwtSettings.Value;
    }

    public override string CreateToken(int userId, string siteUrl)
        => CreateToken(new UserInfo(userId, default, siteUrl));

    public override string CreateToken(UserInfo userInfo)
    {
        var expiration = DateTimeOffset.UtcNow.AddMinutes(_jwtSettings.MultiFactorAuthExpiryMinutes);
        var token = GenerateUniqueToken(128);

        StoreToken(token, userInfo with { Expiry = expiration }, _jwtSettings.SingleSessionPerUser);

        return token;
    }
}
