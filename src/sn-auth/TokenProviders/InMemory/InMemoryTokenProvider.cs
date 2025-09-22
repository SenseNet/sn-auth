using System.Collections.Concurrent;
using System.Text;

namespace SenseNetAuth.TokenProviders.InMemory;

public abstract class InMemoryTokenProvider : ITokenProvider
{
    protected readonly ConcurrentDictionary<string, UserInfo> tokens = [];

    private static readonly Random _random = new();
    private const int DEFAULT_TOKEN_SIZE = 128;

    public string CreateToken(UserInfo userInfo) => CreateToken(userInfo.UserId, userInfo.SiteUrl);

    public abstract string CreateToken(int userId, string siteUrl);

    public bool IsTokenValid(string token)
    {
        if (tokens.TryGetValue(token, out var value))
        {
            if (value.Expiry >= DateTimeOffset.UtcNow)
                return true;

            tokens.TryRemove(token, out _);
        }

        return false;
    }

    public UserInfo? GetValidUserInfo(string token)
    {
        if (tokens.TryGetValue(token, out var value))
        {
            if (value.Expiry >= DateTimeOffset.UtcNow)
                return value;

            tokens.TryRemove(token, out _);
        }

        return null;
    }

    public void InvalidateToken(string token) => tokens.TryRemove(token, out _);

    public void InvalidateToken(UserInfo userInfo) => InvalidateToken(userInfo.UserId, userInfo.SiteUrl);

    public void InvalidateToken(int userId, string siteUrl)
    {
        foreach (var s in tokens.Where(kv => kv.Value.UserId == userId && kv.Value.SiteUrl == siteUrl).ToList())
        {
            tokens.TryRemove(s.Key, out _);
        }
    }

    public UserInfo? GetUserInfoByToken(string token)
    {
        var found = tokens.TryGetValue(token, out var value);

        return found ? value : null;
    }

    protected static string GenerateUniqueToken(int length = DEFAULT_TOKEN_SIZE)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var token = new StringBuilder(length);

        for (int i = 0; i < length; i++)
        {
            token.Append(chars[_random.Next(chars.Length)]);
        }

        return token.ToString();
    }
}