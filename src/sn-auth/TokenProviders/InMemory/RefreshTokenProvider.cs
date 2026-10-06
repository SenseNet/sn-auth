using Microsoft.Extensions.Options;
using SenseNetAuth.Models.Options;

namespace SenseNetAuth.TokenProviders.InMemory;

public class RefreshTokenProvider : InMemoryTokenProvider
{
    private readonly JwtSettings _jwtSettings;

    public RefreshTokenProvider(IOptions<JwtSettings> options)
    {
        _jwtSettings = options.Value;
    }

    public override string CreateToken(int userId, string siteUrl)
        => CreateToken(new UserInfo(userId, default, siteUrl));

    public override string CreateToken(UserInfo userInfo)
    {
        var expiration = new DateTimeOffset(DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryDays));
        var token = GenerateUniqueToken();

        StoreToken(token, userInfo with { Expiry = expiration }, _jwtSettings.SingleSessionPerUser);

        return token;
    }
}
