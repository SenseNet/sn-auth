using Microsoft.Extensions.Options;
using SenseNet.Client;
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
    {
        var expiration = new DateTimeOffset(DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryDays));
        var token = GenerateUniqueToken();

        InvalidateToken(userId, siteUrl);
        tokens.TryAdd(token, (userId, expiration, siteUrl));

        return token;
    }
}
