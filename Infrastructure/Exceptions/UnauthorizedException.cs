namespace SenseNetAuth.Infrastructure.Exceptions;

public class UnauthorizedException : BaseException
{
    public override int HttpResponseCode => 401;

    public UnauthorizedException(string errorMessage)
    {
        ErrorMessage = errorMessage;
    }
}
