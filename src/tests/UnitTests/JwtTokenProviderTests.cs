using Microsoft.Extensions.Options;
using SenseNetAuth.TokenProviders.InMemory;

namespace TestProject1
{
    public class JwtTokenProviderTests
    {
        [Fact]
        public void CreateToken_ShouldSucceed()
        {
            var settings = new SenseNetAuth.Models.Options.JwtSettings
            {
                SecretKey = "your-256-256-bit-secret123456789",
                TokenExpiryMinutes = 60,
                Issuer = "your-issuer",
                Audience = "sensenet"
            };

            var sut = new JwtTokenProvider(Options.Create(settings));

            var token = sut.CreateToken(1, "http://example.com");

            Assert.NotNull(token);
        }
    }
}