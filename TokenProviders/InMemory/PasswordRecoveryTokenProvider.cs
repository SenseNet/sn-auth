using Microsoft.Extensions.Options;
using SenseNet.Client;
using SenseNetAuth.Models.Options;
using System.Security.Cryptography;

namespace SenseNetAuth.TokenProviders.InMemory;

public class PasswordRecoveryTokenProvider : InMemoryTokenProvider
{
    private readonly PasswordRecoverySettings _passwordRecoverySettings;

    public PasswordRecoveryTokenProvider(IOptions<PasswordRecoverySettings> options)
    {
        _passwordRecoverySettings = options.Value;
    }

    public override string CreateToken(int userId)
    {
        var expiration = new DateTimeOffset(DateTime.UtcNow.AddDays(_passwordRecoverySettings.TokenExpiryMinutes));
        var token = GenerateUniqueToken(128);

        InvalidateToken(userId);
        tokens.Add(token, (userId, expiration));

        return token;
    }
}
