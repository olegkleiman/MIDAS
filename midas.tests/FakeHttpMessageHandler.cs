using System.Net.Http;
using System.Net;
using System.Threading.Tasks;
using System.Threading;

public class FakeHttpMessageHandler : HttpMessageHandler
{
    private readonly HttpResponseMessage _response;

    public FakeHttpMessageHandler(HttpResponseMessage response)
    {
        _response = response;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Можно проверить URL или тело запроса, если нужно
        return Task.FromResult(_response);
    }
}
