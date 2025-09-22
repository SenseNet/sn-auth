using SenseNet.Client;

namespace IntegrationTests.Fakes
{
    internal class TestRestCaller : IRestCaller
    {
        private string server;

        public TestRestCaller(string server)
        {
            this.server = server;
        }

        public ServerContext Server { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public Task<string> GetResponseStringAsync(Uri uri, HttpMethod method, string postData, Dictionary<string, IEnumerable<string>> additionalHeaders, CancellationToken cancel)
        {
            throw new NotImplementedException();
        }

        public Task ProcessWebRequestResponseAsync(string relativeUrl, HttpMethod method, Dictionary<string, IEnumerable<string>> additionalHeaders, Action<HttpClientHandler, HttpClient, HttpRequestMessage> requestProcessor, Func<HttpResponseMessage, CancellationToken, Task> responseProcessor, CancellationToken cancel)
        {
            throw new NotImplementedException();
        }

        public Task ProcessWebResponseAsync(string relativeUrl, HttpMethod method, Dictionary<string, IEnumerable<string>> additionalHeaders, HttpContent postData, Func<HttpResponseMessage, CancellationToken, Task> responseProcessor, CancellationToken cancel)
        {
            throw new NotImplementedException();
        }
    }
}