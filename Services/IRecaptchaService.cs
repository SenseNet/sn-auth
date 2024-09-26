namespace SenseNetAuth.Services;

public interface IRecaptchaService
{
    public Task<bool> ValidateRecaptchaAsync(string recaptchaResponse);
}
