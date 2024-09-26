using SenseNetAuth.Models.Options;

namespace SenseNetAuth.TokenProviders.InMemory;

public class RememberMeTokenProvider : InMemoryTokenProvider
{
    public override string CreateToken(int userId)
    {
        var expiration = new DateTimeOffset(DateTime.UtcNow.AddYears(100));
        var token = GenerateUniqueToken(128);

        InvalidateToken(userId);
        tokens.Add(token, (userId, expiration));

        return token;
    }
}
