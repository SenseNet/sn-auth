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

    public override string CreateToken(int userId)
    {
        var expiration = new DateTimeOffset(DateTime.UtcNow.AddDays(_jwtSettings.AuthTokenExpiryMinutes));
        var token = GenerateUniqueToken(128);

        InvalidateToken(userId);
        tokens.TryAdd(token, (userId, expiration));

        return token;
    }
}
