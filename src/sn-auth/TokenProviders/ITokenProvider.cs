namespace SenseNetAuth.TokenProviders;

public interface ITokenProvider
{
    public string CreateToken(int userId, string siteUrl);
    public string CreateToken(UserInfo userInfo);
    public bool IsTokenValid(string Token);
    public UserInfo? GetValidUserInfo(string token);
    public void InvalidateToken(string token);
    public void InvalidateToken(UserInfo userInfo);
    public UserInfo? GetUserInfoByToken(string token);
}
