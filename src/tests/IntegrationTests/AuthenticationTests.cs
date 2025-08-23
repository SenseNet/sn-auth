using SenseNetAuth.Models;
using Shouldly;
using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;
using Xunit.Abstractions;

namespace IntegrationTests
{
    public class AuthenticationTests : IClassFixture<SensenetAuthApplicationFactory>
    {
        private readonly SensenetAuthApplicationFactory _factory;

        public HttpClient Client { get; private set; }
        public ITestOutputHelper TestOutputHelper { get; }

        public AuthenticationTests(SensenetAuthApplicationFactory factory, ITestOutputHelper testOutputHelper)
        {
            _factory = factory;
            TestOutputHelper = testOutputHelper;
            Client = CreateAuthClient();
        }

        [Fact]
        public async Task LoginPage_ShouldReturnOkStatusAndContainTitle_WhenGetRequestIsMade()
        {
            // Arrange

            // Act
            var response = await Client.GetAsync("/login?redirectUrl=https://localhost&callbackUri=/home");

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var content = await response.Content.ReadAsStringAsync();
            Assert.Contains("Sense/Net Auth - Login", content); // Check for page title or other marker
        }

        [Fact]
        public async Task Login_ShouldRedirectAndReturnAuthCode_WhenValidCredentialsPosted()
        {
            // Arrange
            var formData = new Dictionary<string, string>
            {
                { "LoginName", "test" },
                { "Password", "test" },
                { "RedirectUrl", "https://localhost" },
                { "CallbackUri", "/home" }
            };
            var content = new FormUrlEncodedContent(formData);

            // Act
            var response = await Client.PostAsync("/login", content);

            // Assert
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Assert.NotNull(response.Headers.Location);
            // Extract the auth_code from the redirect URL
            var redirectUrl = response.Headers.Location.ToString();
            var uri = new Uri(redirectUrl);
            var queryParams = System.Web.HttpUtility.ParseQueryString(uri.Query);
            var authCode = queryParams["auth_code"];
            Assert.NotNull(authCode);
        }

        [Fact]
        public async Task LoginAndConvertAuthToken_ShouldReturnValidAccessAndRefreshTokens_WhenAuthCodeIsProvided()
        {
            // Arrange
            var formData = new Dictionary<string, string>
            {
                { "LoginName", "test" },
                { "Password", "test" },
                { "RedirectUrl", "https://localhost" },
                { "CallbackUri", "/home" }
            };
            var content = new FormUrlEncodedContent(formData);

            var authCode = await CallLoginAsync(content);

            // Act
            // Now, call the ConvertAuthToken endpoint
            LoginResponse? loginResponse = await CallConvertAuthTokenAsync(authCode);

            // Assert
            loginResponse.ShouldNotBeNull();
            loginResponse.AccessToken.ShouldNotBeEmpty();
            loginResponse.RefreshToken.ShouldNotBeEmpty();
        }

        [Fact]
        public async Task MultipleLoginsInSameApplication_ShouldInvalidateFirstToken_AndSecondTokenShouldBeValid()
        {
            // Arrange
            var getLoginResponse = await GetLoginResponseAsync("https://localhost", "/home");
            await Task.Delay(1000); // Ensure there's a slight delay to differentiate the tokens
            var getLoginResponseSecond = await GetLoginResponseAsync("https://localhost", "/home");

            TestOutputHelper.WriteLine("First login and second  access token equals: " + (getLoginResponse.AccessToken == getLoginResponseSecond.AccessToken).ToString());

            // Act
            Client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", getLoginResponse.AccessToken);
            var firstLoginAccessTokenValidationResponse = await Client.GetAsync("api/auth/validate-token");
            TestOutputHelper.WriteLine("First login access token validation response: " + firstLoginAccessTokenValidationResponse.StatusCode);

            Client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", getLoginResponseSecond.AccessToken);
            var secondLoginAccessTokenValidationResponse = await Client.GetAsync("api/auth/validate-token");
            TestOutputHelper.WriteLine("Second login access token validation response: " + secondLoginAccessTokenValidationResponse.StatusCode);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, firstLoginAccessTokenValidationResponse.StatusCode);
            Assert.Equal(HttpStatusCode.OK, secondLoginAccessTokenValidationResponse.StatusCode);
        }

        [Fact]
        public async Task LoginWithDifferentApplications_ShouldReturnValidTokensForBothSessions()
        {
            // Arrange
            var loginResponse = await GetLoginResponseAsync("https://localhost", "/home");
            await Task.Delay(1000); // Ensure there's a slight delay to differentiate the tokens
            var secondLoginResponse = await GetLoginResponseAsync("https://localhost:8080", "/home");

            // Act
            Client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", loginResponse.AccessToken);
            var firstLoginAccessTokenValidationResponse = await Client.GetAsync("api/auth/validate-token");

            Client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", secondLoginResponse.AccessToken);
            var secondLoginAccessTokenValidationResponse = await Client.GetAsync("api/auth/validate-token");

            // Assert
            loginResponse.AuthToken.ShouldNotBe(secondLoginResponse.AccessToken);
            Assert.Equal(HttpStatusCode.OK, firstLoginAccessTokenValidationResponse.StatusCode);
            Assert.Equal(HttpStatusCode.OK, secondLoginAccessTokenValidationResponse.StatusCode);
        }

        internal async Task<LoginResponse> GetLoginResponseAsync(string redirectUrl, string callbackUrl)
        {
            var formData = new Dictionary<string, string>
            {
                { "LoginName", "test" },
                { "Password", "test" },
                { "RedirectUrl",redirectUrl },
                { "CallbackUri",  callbackUrl }
            };
            var content = new FormUrlEncodedContent(formData);

            var authCode = await CallLoginAsync(content);

            TestOutputHelper.WriteLine("authCode:" + authCode);
            LoginResponse? loginResponse = await CallConvertAuthTokenAsync(authCode);

            loginResponse.ShouldNotBeNull();
            loginResponse.AccessToken.ShouldNotBeEmpty();
            loginResponse.RefreshToken.ShouldNotBeEmpty();
            return loginResponse;
        }

        private HttpClient CreateAuthClient()
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false // Do not follow redirects automatically
            };

            var client = _factory.CreateDefaultClient(new DelegatingHandlerAdapter(handler)); // Wrap HttpClientHandler
            client.Timeout = TimeSpan.FromMinutes(5);
            return client;
        }

        private async Task<LoginResponse?> CallConvertAuthTokenAsync(string authCode)
        {
            var tokenRequest = new { Token = authCode };
            var convertContent = new StringContent(
                System.Text.Json.JsonSerializer.Serialize(tokenRequest),
                Encoding.UTF8,
                "application/json"
            );

            var convertResponse = await Client.PostAsync("api/auth/convert-auth-token", convertContent);

            // Assert
            Assert.Equal(HttpStatusCode.OK, convertResponse.StatusCode);
            var responseBody = await convertResponse.Content.ReadAsStringAsync();
            var loginResponse = JsonSerializer.Deserialize<LoginResponse>(responseBody, JsonSerializerOptions.Web);
            return loginResponse;
        }

        private async Task<string?> CallLoginAsync(FormUrlEncodedContent content)
        {
            var response = await Client.PostAsync("/login", content);

            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            var redirectUrl = response.Headers.Location.ToString();

            // Extract the auth_code from the redirect URL
            var uri = new Uri(redirectUrl);
            var queryParams = System.Web.HttpUtility.ParseQueryString(uri.Query);
            var authCode = queryParams["auth_code"];
            return authCode;
        }
    }

    // Helper class to adapt HttpClientHandler to DelegatingHandler
    public class DelegatingHandlerAdapter : DelegatingHandler
    {
        public DelegatingHandlerAdapter(HttpMessageHandler innerHandler)
        {
            InnerHandler = innerHandler;
        }
    }
}