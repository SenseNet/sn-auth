using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using SenseNet.Client;
using SenseNetAuth.Models.Options;
using System.Security.Cryptography;

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
        tokens.Add(token, (userId, expiration));

        return token;
    }
}
