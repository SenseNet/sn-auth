using Microsoft.Extensions.Options;
using SenseNetAuth.Models;
using SenseNetAuth.Models.Options;
using SenseNetAuth.TokenProviders;
using SenseNetAuth.TokenProviders.InMemory;

namespace TestProject1;

public class TemporaryCodeExpiryTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void TemporaryCodeExpirySettingsAreMinutesForBothCreationOverloads(bool mfa, bool includeSession)
    {
        var provider = CreateProvider(mfa, 3);
        var binding = new AuthorizationCodeBinding(new string('s', 43), new string('c', 43), "https://admin.example/callback");
        var user = new UserInfo(1, DateTimeOffset.UtcNow.AddDays(1), "https://repo.example")
        {
            SessionId = "existing-session", AuthorizationCodeBinding = binding
        };
        var before = DateTimeOffset.UtcNow;
        var token = includeSession ? provider.CreateToken(user) : provider.CreateToken(user.UserId, user.SiteUrl);
        var after = DateTimeOffset.UtcNow;
        var saved = provider.GetValidUserInfo(token);

        Assert.True(saved.HasValue);
        Assert.InRange(saved.Value.Expiry, before.AddMinutes(3), after.AddMinutes(3));
        Assert.Equal(user.UserId, saved.Value.UserId);
        Assert.Equal(user.SiteUrl, saved.Value.SiteUrl);
        if (includeSession)
        {
            Assert.Equal(user.SessionId, saved.Value.SessionId);
            Assert.Equal(binding, saved.Value.AuthorizationCodeBinding);
        }
        Assert.NotNull(provider.ConsumeToken(token));
        Assert.Null(provider.ConsumeToken(token));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExpiredTemporaryCodesCannotBeValidatedOrConsumed(bool mfa)
    {
        var provider = CreateProvider(mfa, -1);
        var checkedCode = provider.CreateToken(1, "https://repo.example");
        var consumedCode = provider.CreateToken(2, "https://repo.example");

        Assert.False(provider.IsTokenValid(checkedCode));
        Assert.Null(provider.GetValidUserInfo(checkedCode));
        Assert.Null(provider.ConsumeToken(consumedCode));
    }

    private static InMemoryTokenProvider CreateProvider(bool mfa, int minutes)
    {
        var options = Options.Create(new JwtSettings
        {
            AuthTokenExpiryMinutes = mfa ? minutes + 9 : minutes,
            MultiFactorAuthExpiryMinutes = mfa ? minutes : minutes + 9
        });
        return mfa ? new MultiFactorAuthTokenProvider(options) : new AuthTokenProvider(options);
    }
}
