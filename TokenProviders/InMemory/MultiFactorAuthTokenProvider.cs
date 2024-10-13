using Microsoft.Extensions.Options;
using SenseNet.Client;
using SenseNetAuth.Models.Options;
using System.Security.Cryptography;

namespace SenseNetAuth.TokenProviders.InMemory;

public class MultiFactorAuthTokenProvider : InMemoryTokenProvider
{
    private readonly JwtSettings _jwtSettings;

    public MultiFactorAuthTokenProvider(IOptions<JwtSettings> jwtSettings)
    {
        _jwtSettings = jwtSettings.Value;
    }

    public override string CreateToken(int userId)
    {
        var expiration = new DateTimeOffset(DateTime.UtcNow.AddDays(_jwtSettings.MultiFactorAuthExpiryMinutes));
        var token = GenerateUniqueToken(128);

        InvalidateToken(userId);
        tokens.TryAdd(token, (userId, expiration));

        return token;
    }
}
