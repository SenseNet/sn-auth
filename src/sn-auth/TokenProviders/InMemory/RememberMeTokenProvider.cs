namespace SenseNetAuth.TokenProviders.InMemory;

public class RememberMeTokenProvider : InMemoryTokenProvider
{
    private readonly bool _singleSessionPerUser;

    public RememberMeTokenProvider() : this(false) { }

    public RememberMeTokenProvider(bool singleSessionPerUser)
    {
        _singleSessionPerUser = singleSessionPerUser;
    }

    public override string CreateToken(int userId, string siteUrl)
    {
        var expiration = new DateTimeOffset(DateTime.UtcNow.AddYears(100));
        var token = GenerateUniqueToken(128);

        StoreToken(token, new UserInfo(userId, expiration, siteUrl), _singleSessionPerUser);

        return token;
    }
}
