namespace SenseNetAuth.Infrastructure.Exceptions;

public abstract class BaseException : Exception
{
    public abstract int HttpResponseCode { get; }
    public string ErrorMessage { get; set; } = string.Empty;
}
