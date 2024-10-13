using Serilog;
using System.Text;

namespace SenseNetAuth.Infrastructure.Middlewares;

public class RequestResponseLoggerMiddleware
{
    private readonly RequestDelegate _next;

    public RequestResponseLoggerMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context)
    {
        context.Request.EnableBuffering();
        var requestBody = await ReadStreamAsync(context.Request.Body);
        Log.Information("[Request - {date}] Method:{method} Path:{url}", DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"),
            context.Request.Method, context.Request.Path);
        context.Request.Body.Position = 0;

        var originalResponseBodyStream = context.Response.Body;
        using var responseBodyStream = new MemoryStream();
        context.Response.Body = responseBodyStream;

        await _next(context);

        context.Response.Body.Seek(0, SeekOrigin.Begin);
        var responseBody = await ReadStreamAsync(context.Response.Body);
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        Log.Information("[Response - {date}] Path:{url} StatusCode:{statusCode}", DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"),
            context.Request.Path, context.Response.StatusCode);

        await responseBodyStream.CopyToAsync(originalResponseBodyStream);
    }

    private async Task<string> ReadStreamAsync(Stream stream)
    {
        stream.Seek(0, SeekOrigin.Begin);
        using var reader = new StreamReader(stream, Encoding.UTF8, true, 1024, true);
        var text = await reader.ReadToEndAsync();
        stream.Seek(0, SeekOrigin.Begin);
        return text;
    }
}
