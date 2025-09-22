namespace SenseNetAuth.TokenProviders.InMemory;

public class RememberMeTokenProvider : InMemoryTokenProvider
{
    public override string CreateToken(int userId, string siteUrl)
    {
        var expiration = new DateTimeOffset(DateTime.UtcNow.AddYears(100));
        var token = GenerateUniqueToken(128);

        InvalidateToken(userId, siteUrl);
        tokens.TryAdd(token, (userId, expiration, siteUrl));

        return token;
    }
}
