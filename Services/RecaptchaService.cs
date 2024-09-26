
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using SenseNetAuth.Models;
using SenseNetAuth.Models.Options;

namespace SenseNetAuth.Services;

public class RecaptchaService : IRecaptchaService
{
    private readonly RecaptchaSettings _recaptchaSettings;

    public RecaptchaService(
        IOptions<RecaptchaSettings> options
    )
    {
        _recaptchaSettings = options.Value;
    }

    public async Task<bool> ValidateRecaptchaAsync(string recaptchaResponse)
    {
        using var client = new HttpClient();
        var response = await client.PostAsync(
            $"https://www.google.com/recaptcha/api/siteverify?secret={_recaptchaSettings.SecretKey}&response={recaptchaResponse}",
            new StringContent(""));

        if (response.StatusCode != System.Net.HttpStatusCode.OK)
            return false;

        var jsonResponse = await response.Content.ReadAsStringAsync();
        var recaptchaResult = JsonConvert.DeserializeObject<RecaptchaResponse>(jsonResponse);

        return recaptchaResult != null && recaptchaResult.Success && recaptchaResult.Score > 0.5;
    }
}
