using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Moq;
using SenseNetAuth.Models;
using SenseNetAuth.Services;
using Xunit;

namespace IntegrationTests;

public class ExternalLoginFlowTests : IClassFixture<SensenetAuthApplicationFactory>
{
    private const string State = "browser_state_012345678901234567890123456789";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Callback = "/authentication/login-callback?existing=one&next=two";
    private static readonly string Challenge = WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(Verifier)));
    private readonly SensenetAuthApplicationFactory _factory;

    public ExternalLoginFlowTests(SensenetAuthApplicationFactory factory) => _factory = factory;

    private HttpClient Client(WebApplicationFactory<SenseNetAuth.Program>? factory = null) =>
        (factory ?? _factory).CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    private static Dictionary<string, string> Form() => new()
    {
        ["LoginName"] = "test", ["Password"] = "test", ["RedirectUrl"] = "https://localhost",
        ["CallbackUri"] = Callback, ["State"] = State, ["CodeChallenge"] = Challenge, ["CodeChallengeMethod"] = "S256"
    };

    [Fact]
    public async Task PasswordLoginEchoesStateAndPreservesCallbackQueryAndRequiresProof()
    {
        using var client = Client();
        var login = await client.PostAsync("/login", new FormUrlEncodedContent(Form()));
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        var callback = login.Headers.Location!;
        var query = QueryHelpers.ParseQuery(callback.Query);
        Assert.Equal("/authentication/login-callback", callback.AbsolutePath);
        Assert.Equal("one", query["existing"]);
        Assert.Equal("two", query["next"]);
        Assert.Equal(State, query["state"]);
        var code = query["auth_code"].ToString();
        var wrong = await client.PostAsJsonAsync("/api/auth/convert-auth-token", new { token = code, codeVerifier = new string('x', 43) });
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        var valid = await client.PostAsJsonAsync("/api/auth/convert-auth-token", new { token = code, codeVerifier = Verifier });
        Assert.Equal(HttpStatusCode.OK, valid.StatusCode);
        var tokens = await valid.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.False(string.IsNullOrEmpty(tokens!.AccessToken));
        var replay = await client.PostAsJsonAsync("/api/auth/convert-auth-token", new { token = code, codeVerifier = Verifier });
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Theory]
    [InlineData("https://elsewhere.example/callback")]
    [InlineData("//elsewhere.example/callback")]
    [InlineData("http://localhost/callback")]
    [InlineData("https://localhost:8080/callback")]
    public async Task LoginDoesNotSendCodeToAnotherOrigin(string callback)
    {
        using var client = Client();
        var form = Form();
        form["CallbackUri"] = callback;
        var response = await client.PostAsync("/login", new FormUrlEncodedContent(form));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.DoesNotContain("name=\"Password\"", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task PartialBindingCannotSilentlyCreateALegacyCode()
    {
        using var client = Client();
        var form = Form();
        form.Remove("CodeChallengeMethod");
        var response = await client.PostAsync("/login", new FormUrlEncodedContent(form));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task NavigationAndValidationRetriesKeepEncodedBindingContext()
    {
        using var client = Client();
        var query = QueryString(Form());
        var loginHtml = await client.GetStringAsync("/login" + query);
        Assert.Contains($"name=\"State\" value=\"{State}\"", loginHtml);
        Assert.Contains("callbackUri=%2Fauthentication%2Flogin-callback%3Fexisting%3Done%26next%3Dtwo", loginHtml);
        Assert.Contains("codeChallengeMethod=S256", loginHtml);
        foreach (var path in new[] { "/forgottenPassword", "/passwordRecovery" })
        {
            var html = await client.GetStringAsync(path + query);
            Assert.Contains($"name=\"State\" value=\"{State}\"", html);
            Assert.Contains($"name=\"CodeChallenge\" value=\"{Challenge}\"", html);
            Assert.Contains("codeChallengeMethod=S256", html);
        }
        foreach (var path in new[] { "/registration", "/passwordRecovery" })
        {
            var form = Form();
            form["Password"] = "one";
            form["ConfirmPassword"] = "two";
            var response = await client.PostAsync(path, new FormUrlEncodedContent(form));
            var html = await response.Content.ReadAsStringAsync();
            Assert.Contains($"name=\"State\" value=\"{State}\"", html);
            Assert.Contains($"name=\"CodeChallenge\" value=\"{Challenge}\"", html);
        }
        var registration = await client.GetAsync("/registration" + query);
        if (registration.StatusCode == HttpStatusCode.Redirect)
            Assert.Equal(State, QueryHelpers.ParseQuery(new Uri(client.BaseAddress!, registration.Headers.Location!).Query)["state"]);
    }

    [Fact]
    public async Task ForgottenPasswordEmailContextKeepsStateAndEncodedCallback()
    {
        var service = new Mock<IAuthService>();
        string? context = null;
        service.Setup(s => s.ForgottenPasswordAsync(It.IsAny<ForgottenPasswordRequest>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Callback<ForgottenPasswordRequest, string, CancellationToken>((_, value, _) => context = value)
            .Returns(Task.CompletedTask);
        using var factory = _factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IAuthService>();
            services.AddSingleton(service.Object);
        }));
        using var client = Client(factory);
        var form = Form();
        form["Email"] = "test@example.invalid";
        var response = await client.PostAsync("/forgottenPassword", new FormUrlEncodedContent(form));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(context);
        var query = QueryHelpers.ParseQuery(context);
        Assert.Equal(Callback, query["callbackUri"]);
        Assert.Equal(State, query["state"]);
        Assert.Equal(Challenge, query["codeChallenge"]);
    }

    [Fact]
    public async Task SuccessfulRecoveryRedirectKeepsTheBoundLoginContext()
    {
        var service = new Mock<IAuthService>();
        service.Setup(s => s.PasswordRecoveryAsync(It.IsAny<PasswordRecoveryRequest>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        using var factory = _factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IAuthService>();
            services.AddSingleton(service.Object);
        }));
        using var client = Client(factory);
        var form = Form();
        form["ConfirmPassword"] = form["Password"];
        form["Token"] = "synthetic-recovery-token";
        var response = await client.PostAsync("/passwordRecovery", new FormUrlEncodedContent(form));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var destination = new Uri(client.BaseAddress!, response.Headers.Location!);
        Assert.Equal("/Login", destination.AbsolutePath);
        var query = QueryHelpers.ParseQuery(destination.Query);
        Assert.Equal(Callback, query["callbackUri"]);
        Assert.Equal(State, query["state"]);
        Assert.Equal(Challenge, query["codeChallenge"]);
        Assert.Equal("S256", query["codeChallengeMethod"]);
        var login = await client.GetStringAsync(destination);
        Assert.Contains($"name=\"State\" value=\"{State}\"", login);
    }

    [Fact]
    public async Task MfaUsesOriginalBoundCallbackAndStateAndKeepsBindingOnRetry()
    {
        var users = new Mock<IUserService>();
        users.Setup(s => s.ValidateCredentialsAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(1);
        users.Setup(s => s.GetMultiFactorAuthenticationInfoAsync(1, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MultiFactorInfoResponse { MultiFactorEnabled = true, MultiFactorRegistered = true });
        users.Setup(s => s.ValidateTwoFactorCodeAsync(1, It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((int _, string code, CancellationToken _) => code == "123456");
        using var factory = _factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IUserService>();
            services.AddSingleton(users.Object);
        }));
        using var client = Client(factory);
        var response = await client.PostAsync("/login", new FormUrlEncodedContent(Form()));
        var html = await response.Content.ReadAsStringAsync();
        var token = System.Text.RegularExpressions.Regex.Match(html, "name=\"MultiFactorAuthToken\" value=\"([^\"]+)\"").Groups[1].Value;
        Assert.NotEmpty(token);
        var form = Form();
        form["MultiFactorAuthToken"] = token;
        form["MultiFactorCode"] = "wrong";
        var retry = await client.PostAsync("/multiFactorAuth", new FormUrlEncodedContent(form));
        Assert.Contains($"name=\"State\" value=\"{State}\"", await retry.Content.ReadAsStringAsync());
        form["MultiFactorCode"] = "123456";
        form["State"] = new string('a', 43);
        form["CallbackUri"] = "/tampered";
        var success = await client.PostAsync("/multiFactorAuth", new FormUrlEncodedContent(form));
        Assert.Equal(HttpStatusCode.Redirect, success.StatusCode);
        Assert.Equal("/authentication/login-callback", success.Headers.Location!.AbsolutePath);
        var query = QueryHelpers.ParseQuery(success.Headers.Location.Query);
        Assert.Equal(State, query["state"]);
        var exchange = await client.PostAsJsonAsync("/api/auth/convert-auth-token", new { token = query["auth_code"].ToString(), codeVerifier = Verifier });
        Assert.Equal(HttpStatusCode.OK, exchange.StatusCode);
    }

    private static string QueryString(Dictionary<string, string> form) => Microsoft.AspNetCore.Http.QueryString.Create(
        form.Where(pair => pair.Key != "Password" && pair.Key != "LoginName").Select(pair => new KeyValuePair<string, string?>(pair.Key, pair.Value))).ToString();
}
