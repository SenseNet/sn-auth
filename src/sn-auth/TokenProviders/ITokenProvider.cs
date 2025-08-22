namespace SenseNetAuth.TokenProviders;

public interface ITokenProvider
{
    public string CreateToken(int userId);
    public bool IsTokenValid(string Token);
    public void InvalidateToken(string token);
    public void InvalidateToken(int userId);
    public int? GetUserIdByToken(string token);
}
