using System.Collections.Concurrent;
using System.Text;
using System.Security.Cryptography;

namespace SenseNetAuth.TokenProviders.InMemory;

public abstract class InMemoryTokenProvider : ITokenProvider
{
    protected readonly ConcurrentDictionary<string, UserInfo> tokens = [];

    private const int DEFAULT_TOKEN_SIZE = 128;

    public virtual string CreateToken(UserInfo userInfo) => CreateToken(userInfo.UserId, userInfo.SiteUrl);

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

    public void InvalidateSession(UserInfo userInfo)
    {
        foreach (var entry in tokens.Where(kv => kv.Value.UserId == userInfo.UserId
                     && kv.Value.SiteUrl == userInfo.SiteUrl
                     && kv.Value.SessionId == userInfo.SessionId).ToList())
            tokens.TryRemove(entry.Key, out _);
    }

    public UserInfo? ConsumeToken(string token)
    {
        return tokens.TryRemove(token, out var value) && value.Expiry >= DateTimeOffset.UtcNow
            ? value
            : null;
    }

    protected void StoreToken(string token, UserInfo userInfo, bool singleSessionPerUser,
        bool replaceSessionTokens = true)
    {
        // Opportunistic cleanup keeps expired sessions from accumulating between logins.
        foreach (var entry in tokens.Where(kv => kv.Value.Expiry < DateTimeOffset.UtcNow).ToList())
            tokens.TryRemove(entry.Key, out _);

        if (string.IsNullOrEmpty(userInfo.SessionId))
            userInfo = userInfo with { SessionId = Guid.NewGuid().ToString("N") };

        if (singleSessionPerUser)
        {
            foreach (var entry in tokens.Where(kv => kv.Value.UserId == userInfo.UserId
                         && kv.Value.SiteUrl == userInfo.SiteUrl
                         && (replaceSessionTokens || kv.Value.SessionId != userInfo.SessionId)).ToList())
                tokens.TryRemove(entry.Key, out _);
        }
        else if (replaceSessionTokens)
            InvalidateSession(userInfo);

        if (!tokens.TryAdd(token, userInfo))
            throw new InvalidOperationException("A token with this identifier already exists.");
    }

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
            token.Append(chars[RandomNumberGenerator.GetInt32(chars.Length)]);
        }

        return token.ToString();
    }
}
