using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SenseNetAuth.Models;
using SenseNetAuth.Models.Options;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Xunit;

namespace IntegrationTests;

public class SessionEndpointTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SeparateBrowserClientsCanRefreshAndLogoutAccordingToTheConfiguredPolicy(bool singleSession)
    {
        using var factory = new SensenetAuthApplicationFactory();
        using var configured = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.PostConfigure<JwtSettings>(options => options.SingleSessionPerUser = singleSession)));
        using var firstBrowser = configured.CreateClient();
        using var secondBrowser = configured.CreateClient();
        var first = await Login(firstBrowser);
        var second = await Login(secondBrowser);

        Assert.NotEqual(first.AccessToken, second.AccessToken);
        Assert.Equal(singleSession ? HttpStatusCode.Unauthorized : HttpStatusCode.OK,
            await Validate(firstBrowser, first.AccessToken));
        Assert.Equal(HttpStatusCode.OK, await Validate(secondBrowser, second.AccessToken));

        using var refreshFirst = await firstBrowser.PostAsJsonAsync("/api/auth/refresh-token",
            new TokenRequest { Token = first.RefreshToken });
        if (singleSession)
            Assert.Equal(HttpStatusCode.Unauthorized, refreshFirst.StatusCode);
        else
        {
            Assert.Equal(HttpStatusCode.OK, refreshFirst.StatusCode);
            var rotated = (await refreshFirst.Content.ReadFromJsonAsync<LoginResponse>())!;
            using var replay = await firstBrowser.PostAsJsonAsync("/api/auth/refresh-token",
                new TokenRequest { Token = first.RefreshToken });
            Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
            await Logout(firstBrowser, first.AccessToken);
            Assert.Equal(HttpStatusCode.Unauthorized, await Validate(firstBrowser, rotated.AccessToken));
            using var afterLogout = await firstBrowser.PostAsJsonAsync("/api/auth/refresh-token",
                new TokenRequest { Token = rotated.RefreshToken });
            Assert.Equal(HttpStatusCode.Unauthorized, afterLogout.StatusCode);
        }

        // Even a stale first-browser logout must not revoke the second browser.
        await Logout(firstBrowser, first.AccessToken);
        using var refreshSecond = await secondBrowser.PostAsJsonAsync("/api/auth/refresh-token",
            new TokenRequest { Token = second.RefreshToken });
        Assert.Equal(HttpStatusCode.OK, refreshSecond.StatusCode);
        var secondRotated = (await refreshSecond.Content.ReadFromJsonAsync<LoginResponse>())!;
        Assert.Equal(HttpStatusCode.OK, await Validate(secondBrowser, secondRotated.AccessToken));
    }

    private static async Task<LoginResponse> Login(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            LoginName = "test", Password = "test", SiteUrl = "https://adminui.test.sensenet.com"
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<LoginResponse>())!;
    }

    private static async Task<HttpStatusCode> Validate(HttpClient client, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/validate-token");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request);
        return response.StatusCode;
    }

    private static async Task Logout(HttpClient client, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/logout");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
