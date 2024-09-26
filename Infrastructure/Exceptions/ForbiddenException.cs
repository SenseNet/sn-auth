namespace SenseNetAuth.Infrastructure.Exceptions;

public class ForbiddenException : BaseException
{
    public override int HttpResponseCode => 401;

    public ForbiddenException(string errorMessage)
    {
        ErrorMessage = errorMessage;
    }
}
