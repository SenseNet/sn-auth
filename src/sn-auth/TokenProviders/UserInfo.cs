namespace SenseNetAuth.TokenProviders;

public record struct UserInfo(int UserId, DateTimeOffset Expiry, string SiteUrl)
{
    public static implicit operator UserInfo((int UserId, DateTimeOffset Expiry, string siteUrl) value)
    {
        return new UserInfo(value.UserId, value.Expiry, value.siteUrl);
    }
}