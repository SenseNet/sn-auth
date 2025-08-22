using System.Collections.Concurrent;
using System.Text;

namespace SenseNetAuth.TokenProviders.InMemory;

public abstract class InMemoryTokenProvider : ITokenProvider
{
    protected readonly ConcurrentDictionary<string, (int UserId, DateTimeOffset Expiry)> tokens = [];
    
    private static readonly Random _random = new();
    private const int DEFAULT_TOKEN_SIZE = 128;

    public abstract string CreateToken(int userId);

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

    public void InvalidateToken(string token) => tokens.TryRemove(token, out _);

    public void InvalidateToken(int userId)
    {
        foreach (var s in tokens.Where(kv => kv.Value.UserId == userId).ToList())
        {
            tokens.TryRemove(s.Key, out _);
        }
    }

    public int? GetUserIdByToken(string token)
    {
        var found = tokens.TryGetValue(token, out var value);

        return found ? value.UserId : null;
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
