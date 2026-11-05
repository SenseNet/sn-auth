using Microsoft.Extensions.Options;
using Moq;
using SenseNetAuth.Infrastructure.Exceptions;
using SenseNetAuth.Models;
using SenseNetAuth.Models.Options;
using SenseNetAuth.Services;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace IntegrationTests;

public class AuthorizationCodeBindingTests
{
    private const string Site = "https://adminui.test.sensenet.com";
    private const string Callback = Site + "/authentication/callback?repoUrl=https%3A%2F%2Frepo.example";
    private const string State = "a-valid-browser-state-with-32-characters";
    // RFC 7636 Appendix B: an independently specified S256 test vector.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    [Fact]
    public async Task BoundCodeReturnsTheOriginalFlowAndRequiresItsS256Proof()
    {
        var service = CreateService();
        var pending = await service.AuthenticateAsync(Request(), default);

        Assert.Equal(State, pending.State);
        Assert.Equal(Callback, pending.CallbackUri);
        Assert.NotEmpty(pending.AuthToken);
        Assert.Empty(pending.AccessToken);
        Assert.Empty(pending.RefreshToken);
        var session = Convert(service, pending, Verifier);
        Assert.True(service.ValidateToken(session.AccessToken));
        Assert.True(service.ValidateToken(service.RefreshToken(session.RefreshToken).AccessToken));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("wrong-but-valid-verifier-with-more-than-43-characters")]
    [InlineData("short")]
    [InlineData("invalid verifier containing spaces and more than 43 characters")]
    [InlineData("invalid/verifier/containing/slashes/and/more/than/43/characters")]
    public async Task MissingWrongOrMalformedProofDoesNotConsumeTheBoundCode(string? verifier)
    {
        var service = CreateService();
        var pending = await service.AuthenticateAsync(Request(), default);

        Assert.Throws<UnauthorizedException>(() => Convert(service, pending, verifier));
        Assert.True(service.ValidateToken(Convert(service, pending, Verifier).AccessToken));
    }

    [Theory]
    [InlineData(43)]
    [InlineData(128)]
    public async Task AcceptsBothVerifierLengthLimitsAndUnreservedCharacters(int length)
    {
        var verifier = new string('~', length - 4) + "._-a";
        var request = Request();
        request.CodeChallenge = S256(verifier);
        var service = CreateService();
        var pending = await service.AuthenticateAsync(request, default);

        Assert.True(service.ValidateToken(Convert(service, pending, verifier).AccessToken));
    }

    [Theory]
    [InlineData(42)]
    [InlineData(129)]
    public async Task RejectsVerifierOutsideTheLengthLimitsEvenWhenItsHashMatches(int length)
    {
        var verifier = new string('a', length);
        var request = Request();
        request.CodeChallenge = S256(verifier);
        var service = CreateService();
        var pending = await service.AuthenticateAsync(request, default);

        Assert.Throws<UnauthorizedException>(() => Convert(service, pending, verifier));
        Assert.Throws<UnauthorizedException>(() => Convert(service, pending, null));
    }

    [Theory]
    [InlineData("invalid verifier with spaces and at least 43 characters")]
    [InlineData("invalid/verifier/with/slashes/and/at/least/43/characters")]
    [InlineData("invalid+verifier+with+pluses+and+at+least+43+characters")]
    public async Task RejectsNonUnreservedVerifierCharactersEvenWhenTheirHashMatches(string verifier)
    {
        var request = Request();
        request.CodeChallenge = S256(verifier);
        var service = CreateService();
        var pending = await service.AuthenticateAsync(request, default);

        Assert.Throws<UnauthorizedException>(() => Convert(service, pending, verifier));
    }

    public static IEnumerable<object[]> InvalidBindings()
    {
        yield return new object[] { "", Challenge, "S256" };
        yield return new object[] { State, "", "S256" };
        yield return new object[] { State, Challenge, "" };
        yield return new object[] { State, Challenge, "plain" };
        yield return new object[] { State, Challenge, "s256" };
        yield return new object[] { "too-short", Challenge, "S256" };
        yield return new object[] { new string('a', 513), Challenge, "S256" };
        yield return new object[] { new string('a', 32) + " ", Challenge, "S256" };
        yield return new object[] { State, new string('a', 42), "S256" };
        yield return new object[] { State, new string('a', 44), "S256" };
        yield return new object[] { State, new string('a', 42) + "+", "S256" };
    }

    [Theory]
    [MemberData(nameof(InvalidBindings))]
    public async Task PartialOrMalformedBindingsAreRejectedBeforeCredentialsAreChecked(
        string state, string challenge, string method)
    {
        var users = new Mock<IUserService>(MockBehavior.Strict);
        var service = CreateService(users: users);
        var request = Request();
        request.State = state;
        request.CodeChallenge = challenge;
        request.CodeChallengeMethod = method;

        await Assert.ThrowsAsync<BadRequestException>(() => service.AuthenticateAsync(request, default));
        users.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task AProofCannotRedeemAnotherConcurrentBrowserFlow()
    {
        var service = CreateService();
        var first = await service.AuthenticateAsync(Request(), default);
        var secondRequest = Request();
        var secondVerifier = new string('b', 64);
        secondRequest.State = new string('b', 48);
        secondRequest.CodeChallenge = S256(secondVerifier);
        var second = await service.AuthenticateAsync(secondRequest, default);

        Assert.Throws<UnauthorizedException>(() => Convert(service, first, secondVerifier));
        Assert.Throws<UnauthorizedException>(() => Convert(service, second, Verifier));
        var firstSession = Convert(service, first, Verifier);
        var secondSession = Convert(service, second, secondVerifier);
        Assert.NotEqual(firstSession.AccessToken, secondSession.AccessToken);
        Assert.True(service.ValidateToken(firstSession.AccessToken));
        Assert.True(service.ValidateToken(secondSession.AccessToken));
    }

    [Fact]
    public async Task AProvenCodeCanBeRedeemedOnlyOnce()
    {
        var service = CreateService();
        var pending = await service.AuthenticateAsync(Request(), default);
        var session = Convert(service, pending, Verifier);

        Assert.Throws<UnauthorizedException>(() => Convert(service, pending, Verifier));
        Assert.True(service.ValidateToken(session.AccessToken));
    }

    [Fact]
    public async Task ConcurrentValidProofsCreateExactlyOneSession()
    {
        var service = CreateService();
        var pending = await service.AuthenticateAsync(Request(), default);
        var attempts = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() =>
        {
            try { return Convert(service, pending, Verifier); }
            catch (UnauthorizedException) { return null; }
        })));

        var winner = Assert.Single(attempts.Where(result => result != null))!;
        Assert.True(service.ValidateToken(winner.AccessToken));
        Assert.True(service.ValidateToken(service.RefreshToken(winner.RefreshToken).AccessToken));
    }

    [Fact]
    public async Task InvalidConcurrentProofsCannotBurnTheLegitimateCode()
    {
        var service = CreateService();
        var pending = await service.AuthenticateAsync(Request(), default);
        await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() =>
            Assert.Throws<UnauthorizedException>(() => Convert(service, pending, new string('x', 43))))));

        Assert.True(service.ValidateToken(Convert(service, pending, Verifier).AccessToken));
    }

    [Fact]
    public async Task MfaRetainsTheOriginalCodeBindingUntilProofConversion()
    {
        var service = CreateService(mfa: true);
        var pending = await service.AuthenticateAsync(Request(), default);
        Assert.True(pending.MultiFactorRequired);
        Assert.Empty(pending.AuthToken);
        Assert.Equal(State, pending.State);
        Assert.Equal(Callback, pending.CallbackUri);
        await Assert.ThrowsAsync<BadRequestException>(() => CompleteMfa(service, pending, code: "wrong"));
        var completed = await CompleteMfa(service, pending);

        Assert.Equal(State, completed.State);
        Assert.Equal(Callback, completed.CallbackUri);
        Assert.Empty(completed.AccessToken);
        Assert.Empty(completed.RefreshToken);
        Assert.Throws<UnauthorizedException>(() => Convert(service, completed, null));
        Assert.Throws<UnauthorizedException>(() => Convert(service, completed, new string('x', 43)));
        Assert.True(service.ValidateToken(Convert(service, completed, Verifier).AccessToken));
        await Assert.ThrowsAsync<BadRequestException>(() => CompleteMfa(service, pending));
    }

    [Fact]
    public async Task BoundMfaCannotBypassProofThroughTheDirectLoginEndpoint()
    {
        var service = CreateService(mfa: true);
        var pending = await service.AuthenticateAsync(Request(), default);

        await Assert.ThrowsAsync<BadRequestException>(() => CompleteMfa(service, pending, directLogin: true));
        var completed = await CompleteMfa(service, pending);
        Assert.True(service.ValidateToken(Convert(service, completed, Verifier).AccessToken));
    }

    [Fact]
    public async Task ConcurrentBoundMfaCompletionIssuesExactlyOneProofBoundCode()
    {
        var service = CreateService(mfa: true);
        var pending = await service.AuthenticateAsync(Request(), default);
        var attempts = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(async () =>
        {
            try { return await CompleteMfa(service, pending); }
            catch (BadRequestException) { return null; }
        })));

        var winner = Assert.Single(attempts.Where(result => result != null))!;
        Assert.Equal(State, winner.State);
        Assert.Equal(Callback, winner.CallbackUri);
        Assert.Throws<UnauthorizedException>(() => Convert(service, winner, null));
        Assert.True(service.ValidateToken(Convert(service, winner, Verifier).AccessToken));
    }

    [Theory]
    [InlineData("")]
    [InlineData(Verifier)]
    public async Task ProofBearingClientsRejectLegacyCodeDowngradesWithoutConsumingThem(string rejectedVerifier)
    {
        var service = CreateService();
        var pending = await service.AuthenticateAsync(LegacyRequest(), default);

        Assert.Throws<UnauthorizedException>(() => Convert(service, pending, rejectedVerifier));
        Assert.True(service.ValidateToken(Convert(service, pending, null).AccessToken));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LegacyClientsContinueToWorkWhenAllBindingFieldsAreOmitted(bool mfa)
    {
        var service = CreateService(mfa);
        var pending = await service.AuthenticateAsync(LegacyRequest(), default);
        if (mfa) pending = await CompleteMfa(service, pending);

        Assert.Null(pending.State);
        Assert.Null(pending.CallbackUri);
        Assert.True(service.ValidateToken(Convert(service, pending, null).AccessToken));
    }

    private static LoginRequest LegacyRequest() => new()
    {
        SiteUrl = Site, LoginName = "test-user", Password = "test-password"
    };

    private static LoginRequest Request()
    {
        var request = LegacyRequest();
        request.State = State;
        request.CodeChallenge = Challenge;
        request.CodeChallengeMethod = "S256";
        request.CallbackUri = Callback;
        return request;
    }

    private static LoginResponse Convert(AuthService service, LoginResponse pending, string? verifier)
        => service.ConvertAuthToken(new TokenRequest { Token = pending.AuthToken, CodeVerifier = verifier });

    private static Task<LoginResponse> CompleteMfa(AuthService service, LoginResponse pending,
        bool directLogin = false, string code = "valid") => service.MultiFactorLoginAsync(new MultiFactorLoginRequest
        {
            SiteUrl = Site, MultiFactorAuthToken = pending.MultiFactorAuthToken, MultiFactorCode = code
        }, default, directLogin);

    private static string S256(string verifier) => System.Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)))
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static AuthService CreateService(bool mfa = false, Mock<IUserService>? users = null)
    {
        if (users == null)
        {
            users = new Mock<IUserService>(MockBehavior.Strict);
            users.Setup(u => u.ValidateCredentialsAsync("test-user", "test-password", It.IsAny<CancellationToken>()))
                .ReturnsAsync(1);
            users.Setup(u => u.GetMultiFactorAuthenticationInfoAsync(1, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new MultiFactorInfoResponse { MultiFactorEnabled = mfa, MultiFactorRegistered = true });
            users.Setup(u => u.ValidateTwoFactorCodeAsync(1, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync((int userId, string code, CancellationToken cancel) => code == "valid");
        }
        return new AuthService(users.Object, Options.Create(new JwtSettings
        {
            Issuer = "authorization-code-binding-tests", Audience = "sensenet",
            SecretKey = "test-only-signing-key-with-at-least-32-bytes", TokenExpiryMinutes = 60,
            RefreshTokenExpiryDays = 15, AuthTokenExpiryMinutes = 5, MultiFactorAuthExpiryMinutes = 5
        }), Options.Create(new RegistrationSettings()), Options.Create(new PasswordRecoverySettings()),
            Options.Create(new ApplicationSettings()), Mock.Of<IEmailService>());
    }
}
