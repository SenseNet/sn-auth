using IntegrationTests.Fakes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Moq;
using SenseNetAuth.Infrastructure.Exceptions;
using SenseNetAuth.Models;
using SenseNetAuth.Models.Options;
using SenseNetAuth.Services;
using Xunit;

namespace IntegrationTests;

public class SessionTests
{
    private const string Site = "https://adminui.test.sensenet.com";

    [Fact]
    public async Task DefaultAllowsManyIndependentLoginsForTheSameUserAndApplication()
    {
        var service = CreateService();
        var sessions = new List<LoginResponse>();
        for (var i = 0; i < 8; i++)
            sessions.Add(await Login(service));

        Assert.Equal(8, sessions.Select(s => s.AccessToken).Distinct().Count());
        Assert.All(sessions, s => Assert.True(service.ValidateToken(s.AccessToken)));
        foreach (var session in sessions)
            Assert.True(service.ValidateToken(service.RefreshToken(session.RefreshToken).AccessToken));
    }

    [Fact]
    public async Task SingleSessionOptInInvalidatesPreviousAccessAndRefreshTokens()
    {
        var service = CreateService(singleSession: true);
        var first = await Login(service);
        var second = await Login(service);

        Assert.False(service.ValidateToken(first.AccessToken));
        Assert.Throws<UnauthorizedException>(() => service.RefreshToken(first.RefreshToken));
        Assert.True(service.ValidateToken(second.AccessToken));
        service.Logout(first.AccessToken);
        Assert.True(service.ValidateToken(service.RefreshToken(second.RefreshToken).AccessToken));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DifferentApplicationsAndUsersRemainIndependent(bool singleSession)
    {
        var service = CreateService(singleSession);
        var first = await Login(service);
        var anotherSite = await Login(service, "https://another-admin.example");
        var anotherUser = await Login(service, username: "other-user");

        service.Logout(first.AccessToken);
        Assert.True(service.ValidateToken(anotherSite.AccessToken));
        Assert.True(service.ValidateToken(anotherUser.AccessToken));
        service.RefreshToken(anotherSite.RefreshToken);
        service.RefreshToken(anotherUser.RefreshToken);
    }

    [Fact]
    public async Task RefreshAndLogoutAffectOnlyTheirOwnBrowserSession()
    {
        var service = CreateService();
        var first = await Login(service);
        var second = await Login(service);
        var refreshed = service.RefreshToken(first.RefreshToken);

        Assert.True(service.ValidateToken(second.AccessToken));
        Assert.Throws<UnauthorizedException>(() => service.RefreshToken(first.RefreshToken));
        Assert.True(service.ValidateToken(refreshed.AccessToken));
        service.Logout(refreshed.AccessToken);
        Assert.False(service.ValidateToken(first.AccessToken));
        Assert.False(service.ValidateToken(refreshed.AccessToken));
        Assert.Throws<UnauthorizedException>(() => service.RefreshToken(refreshed.RefreshToken));
        Assert.True(service.ValidateToken(service.RefreshToken(second.RefreshToken).AccessToken));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LogoutWithThePreviousAccessTokenAlsoRevokesTheRefreshedSession(bool singleSession)
    {
        var service = CreateService(singleSession);
        var session = await Login(service);
        var refreshed = service.RefreshToken(session.RefreshToken);
        service.Logout(session.AccessToken);

        Assert.False(service.ValidateToken(refreshed.AccessToken));
        Assert.Throws<UnauthorizedException>(() => service.RefreshToken(refreshed.RefreshToken));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ARefreshTokenCanBeConsumedByOnlyOneConcurrentRequest(bool singleSession)
    {
        var service = CreateService(singleSession);
        var session = await Login(service);
        var results = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() =>
        {
            try { return service.RefreshToken(session.RefreshToken); }
            catch (UnauthorizedException) { return null; }
        })));

        var winner = Assert.Single(results.Where(r => r != null))!;
        Assert.True(service.ValidateToken(winner.AccessToken));
        Assert.True(service.ValidateToken(service.RefreshToken(winner.RefreshToken).AccessToken));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConcurrentRefreshAndLogoutCannotResurrectASession(bool singleSession)
    {
        var service = CreateService(singleSession);
        for (var i = 0; i < 16; i++)
        {
            var session = await Login(service);
            var refresh = Task.Run(() =>
            {
                try { return service.RefreshToken(session.RefreshToken); }
                catch (UnauthorizedException) { return null; }
            });
            await Task.WhenAll(refresh, Task.Run(() => service.Logout(session.AccessToken)));
            Assert.False(service.ValidateToken(session.AccessToken));
            Assert.Throws<UnauthorizedException>(() => service.RefreshToken(session.RefreshToken));
            if (refresh.Result is { } rotated)
            {
                Assert.False(service.ValidateToken(rotated.AccessToken));
                Assert.Throws<UnauthorizedException>(() => service.RefreshToken(rotated.RefreshToken));
            }
        }
    }

    [Fact]
    public async Task ConcurrentLoginsInSingleSessionModeLeaveOnlyOneUsableTokenPair()
    {
        var service = CreateService(singleSession: true);
        var sessions = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() => Login(service))));
        var winner = Assert.Single(sessions.Where(s => service.ValidateToken(s.AccessToken)));
        foreach (var session in sessions.Where(s => s != winner))
            Assert.Throws<UnauthorizedException>(() => service.RefreshToken(session.RefreshToken));
        Assert.True(service.ValidateToken(service.RefreshToken(winner.RefreshToken).AccessToken));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PendingCallbackCodesRespectThePolicyAndAreSingleUse(bool singleSession)
    {
        var service = CreateService(singleSession);
        var first = await service.AuthenticateAsync(Request(), default);
        var second = await service.AuthenticateAsync(Request(), default);
        if (singleSession)
            Assert.Throws<UnauthorizedException>(() => service.ConvertAuthToken(new() { Token = first.AuthToken }));
        else
        {
            var converted = service.ConvertAuthToken(new() { Token = first.AuthToken });
            Assert.True(service.ValidateToken(converted.AccessToken));
        }

        var latest = service.ConvertAuthToken(new() { Token = second.AuthToken });
        Assert.Throws<UnauthorizedException>(() => service.ConvertAuthToken(new() { Token = second.AuthToken }));
        Assert.True(service.ValidateToken(latest.AccessToken));
    }

    [Fact]
    public async Task ConcurrentCallbackConversionCreatesOnlyOneSession()
    {
        var service = CreateService();
        var auth = await service.AuthenticateAsync(Request(), default);
        var results = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() =>
        {
            try { return service.ConvertAuthToken(new() { Token = auth.AuthToken }); }
            catch (UnauthorizedException) { return null; }
        })));
        Assert.Single(results.Where(r => r != null));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task MfaChallengesRespectTheSessionPolicyAndCannotBeReplayed(bool singleSession, bool directLogin)
    {
        var service = CreateService(singleSession, mfa: true);
        var first = directLogin ? await Login(service) : await service.AuthenticateAsync(Request(), default);
        var second = directLogin ? await Login(service) : await service.AuthenticateAsync(Request(), default);
        Assert.True(first.MultiFactorRequired);
        Assert.Empty(first.AccessToken);
        Assert.Empty(first.AuthToken);
        if (singleSession)
            await Assert.ThrowsAsync<BadRequestException>(() => CompleteMfa(service, first, directLogin));
        else
        {
            var firstSession = await CompleteMfa(service, first, directLogin);
            Assert.True(service.ValidateToken(firstSession.AccessToken));
        }

        var session = await CompleteMfa(service, second, directLogin);
        await Assert.ThrowsAsync<BadRequestException>(() => CompleteMfa(service, second, directLogin));
        Assert.True(service.ValidateToken(service.RefreshToken(session.RefreshToken).AccessToken));
    }

    [Fact]
    public async Task InvalidMfaCodeOrChangedApplicationDoesNotConsumeTheChallenge()
    {
        var service = CreateService(mfa: true);
        var challenge = await Login(service);
        await Assert.ThrowsAsync<BadRequestException>(() => service.MultiFactorLoginAsync(new()
        {
            SiteUrl = Site, MultiFactorAuthToken = challenge.MultiFactorAuthToken, MultiFactorCode = "invalid"
        }, default));
        await Assert.ThrowsAsync<BadRequestException>(() => service.MultiFactorLoginAsync(new()
        {
            SiteUrl = "https://another-admin.example", MultiFactorAuthToken = challenge.MultiFactorAuthToken,
            MultiFactorCode = "valid"
        }, default));
        Assert.True(service.ValidateToken((await CompleteMfa(service, challenge, true)).AccessToken));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RememberMeTokensRespectTheSessionPolicy(bool singleSession)
    {
        var service = CreateService(singleSession);
        var request = Request();
        request.RememberMeRequested = true;
        var first = await service.AuthenticateAsync(request, default);
        var second = await service.AuthenticateAsync(request, default);
        var remembered = Request();
        remembered.RememberMeToken = first.RememberMeDetails!.RememberMeToken;
        if (singleSession)
            await Assert.ThrowsAsync<BadRequestException>(() => service.AuthenticateAsync(remembered, default));
        else
            Assert.NotEmpty((await service.AuthenticateAsync(remembered, default)).AuthToken);
        remembered.RememberMeToken = second.RememberMeDetails!.RememberMeToken;
        Assert.NotEmpty((await service.AuthenticateAsync(remembered, default)).AuthToken);
    }

    [Fact]
    public void SingleSessionSettingDefaultsToFalseAndBindsFromEnvironment()
    {
        Assert.False(new JwtSettings().SingleSessionPerUser);
        var prefix = "SNAUTH_SESSION_TEST_" + Guid.NewGuid().ToString("N") + "_";
        var key = prefix + "JwtSettings__SingleSessionPerUser";
        try
        {
            Environment.SetEnvironmentVariable(key, "true");
            var configuration = new ConfigurationBuilder().AddEnvironmentVariables(prefix).Build();
            var settings = configuration.GetSection("JwtSettings").Get<JwtSettings>();
            Assert.True(settings!.SingleSessionPerUser);
        }
        finally { Environment.SetEnvironmentVariable(key, null); }
    }

    private static LoginRequest Request(string site = Site, string username = "test-user")
        => new() { SiteUrl = site, LoginName = username, Password = "test-password" };

    private static Task<LoginResponse> Login(AuthService service, string site = Site, string username = "test-user")
        => service.LoginAsync(Request(site, username), default);

    private static async Task<LoginResponse> CompleteMfa(AuthService service, LoginResponse challenge, bool directLogin)
    {
        var result = await service.MultiFactorLoginAsync(new()
        {
            SiteUrl = Site, MultiFactorAuthToken = challenge.MultiFactorAuthToken, MultiFactorCode = "valid"
        }, default, directLogin);
        return directLogin ? result : service.ConvertAuthToken(new() { Token = result.AuthToken });
    }

    private static AuthService CreateService(bool singleSession = false, bool mfa = false)
    {
        var users = new Mock<IUserService>();
        users.Setup(u => u.ValidateCredentialsAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string username, string password, CancellationToken cancel) => username == "other-user" ? 2 : 1);
        users.Setup(u => u.GetMultiFactorAuthenticationInfoAsync(It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MultiFactorInfoResponse { MultiFactorEnabled = mfa, MultiFactorRegistered = true });
        users.Setup(u => u.ValidateTwoFactorCodeAsync(It.IsAny<int>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((int userId, string code, CancellationToken cancel) => code == "valid");
        var fake = new FakeUserService();
        users.Setup(u => u.GetUserByUserIdAsync(It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .Returns((int userId, CancellationToken cancel) => fake.GetUserByUserIdAsync(userId, cancel));
        return new AuthService(users.Object, Options.Create(new JwtSettings
        {
            SingleSessionPerUser = singleSession, Issuer = "session-tests", Audience = "sensenet",
            SecretKey = "test-only-signing-key-with-at-least-32-bytes", TokenExpiryMinutes = 60,
            RefreshTokenExpiryDays = 15, AuthTokenExpiryMinutes = 5, MultiFactorAuthExpiryMinutes = 5
        }), Options.Create(new RegistrationSettings()), Options.Create(new PasswordRecoverySettings()),
            Options.Create(new ApplicationSettings()), Mock.Of<IEmailService>());
    }
}
