namespace SenseNetAuth.Infrastructure.Exceptions;

public class BadRequestException : BaseException
{
    public override int HttpResponseCode => 400;

    public BadRequestException(string errorMessage)
    {
        ErrorMessage = errorMessage;
    }
}
