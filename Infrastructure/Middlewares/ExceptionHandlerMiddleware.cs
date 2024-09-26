using SenseNetAuth.Infrastructure.Exceptions;
using SenseNetAuth.Models;
using SenseNetAuth.Models.Constants;
using Serilog;
using System.Text.Json;

namespace SenseNetAuth.Infrastructure.Middlewares;

public class ExceptionHandlerMiddleware
{
    private readonly RequestDelegate _next;

    public ExceptionHandlerMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            Log.Error(ex.Message);
            var errorResponse = new ErrorResponse();

            if (ex is BaseException baseException)
            {
                context.Response.StatusCode = baseException.HttpResponseCode;
                errorResponse.StatusCode = baseException.HttpResponseCode;
                errorResponse.ErrorMessage = baseException.ErrorMessage;
            }
            else
            {
                context.Response.StatusCode = 500;
                errorResponse.ErrorMessage = ResponseMessages.InternalServerError;
            }

            var result = JsonSerializer.Serialize(new { errorResponse });
            await context.Response.WriteAsync(result);
        }
    }
}
