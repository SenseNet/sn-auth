using Microsoft.Extensions.Options;
using SenseNetAuth.Models.Options;
using SenseNetAuth.TokenProviders.InMemory;
using System.IdentityModel.Tokens.Jwt;

namespace TestProject1;

public class SessionTokenProviderTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void JwtIdentifiersAreUniqueWithoutWaitingBetweenLogins(bool singleSession)
    {
        var provider = new JwtTokenProvider(Options.Create(new JwtSettings
        {
            SingleSessionPerUser = singleSession, SecretKey = "test-only-signing-key-with-at-least-32-bytes",
            Issuer = "tests", Audience = "sensenet", TokenExpiryMinutes = 60
        }));
        var tokens = Enumerable.Range(0, 32).Select(_ => provider.CreateToken(1, "https://admin.example")).ToArray();
        var handler = new JwtSecurityTokenHandler();
        Assert.Equal(32, tokens.Distinct().Count());
        Assert.Equal(32, tokens.Select(token => handler.ReadJwtToken(token).Id).Distinct().Count());
        Assert.Equal(singleSession ? 1 : 32, tokens.Count(provider.IsTokenValid));
    }

    [Fact]
    public void IssuingANewRefreshTokenRemovesExpiredEntriesAndExpiredTokensCannotBeConsumed()
    {
        var settings = new JwtSettings { RefreshTokenExpiryDays = -1 };
        var provider = new InspectableRefreshProvider(Options.Create(settings));
        var expired = provider.CreateToken(1, "https://admin.example");
        settings.RefreshTokenExpiryDays = 1;
        var valid = provider.CreateToken(1, "https://admin.example");
        Assert.Equal(1, provider.Count);
        Assert.Null(provider.ConsumeToken(expired));
        Assert.NotNull(provider.ConsumeToken(valid));
        Assert.Null(provider.ConsumeToken(valid));
    }

    private sealed class InspectableRefreshProvider(IOptions<JwtSettings> options) : RefreshTokenProvider(options)
    {
        public int Count => tokens.Count;
    }
}
