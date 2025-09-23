using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SenseNetAuth.Infrastructure.Exceptions;
using SenseNetAuth.Models.Constants;
using SenseNetAuth.Models.Options;
using SenseNetAuth.Models.ViewModels;
using SenseNetAuth.Services;

namespace SenseNetAuth.ViewControllers;

public class MultiFactorAuthController : Controller
{
    private readonly IAuthService _authService;
    private readonly IRecaptchaService _recaptchaService;
    private readonly SensenetSettings _sensenetSettings;

    public MultiFactorAuthController(
        IRecaptchaService recaptchaService, 
        IAuthService authService,
        IOptions<SensenetSettings> sensenetOptions)
    {
        _recaptchaService = recaptchaService;
        _authService = authService;
        _sensenetSettings = sensenetOptions.Value;
    }

    [HttpPost("multiFactorAuth")]
    public async Task<IActionResult> PostTwoFactorAuth()
    {
        var errorMessage = string.Empty;
        var isMultiFactorTokenExpired = false;
        if (_recaptchaService.IsConfigured() && !await _recaptchaService.ValidateRecaptchaAsync(Request.Form["g-recaptcha-response"].FirstOrDefault() ?? string.Empty))
        {
            errorMessage = "Invalid ReCaptcha";
        }
        else
        {
            try
            {
                var response = await _authService.MultiFactorLoginAsync(new Models.MultiFactorLoginRequest
                {
                    MultiFactorAuthToken = Request.Form["MultiFactorAuthToken"],
                    MultiFactorCode = Request.Form["MultiFactorCode"],
                    SiteUrl = Request.Form["RedirectUrl"]
                }, HttpContext.RequestAborted, false);

                if (response != null)
                    return Redirect($"{new Uri(new Uri(Request.Form["RedirectUrl"]), Request.Form["CallbackUri"])}?auth_code={response.AuthToken}");
            }
            catch (BadRequestException ex)
            {
                if (ex.ErrorMessage == ResponseMessages.InvalidMultiFactorCode)
                    errorMessage = "Invalid code";
                isMultiFactorTokenExpired = ex.ErrorMessage == ResponseMessages.InvalidMultiFactorToken;
            }
        }

        if (isMultiFactorTokenExpired)
        {
            return View("~/Views/Login/Index", new LoginViewModel
            {
                CallbackUri = Request.Form["CallbackUri"],
                RedirectUrl = Request.Form["RedirectUrl"],
                ErrorMessage = errorMessage
            });
        }
        else
        {
            return View("Index", new MultiFactorViewModel
            {
                RepositoryUrl = _sensenetSettings.Repository.Url,
                CallbackUri = Request.Form["CallbackUri"],
                RedirectUrl = Request.Form["RedirectUrl"],
                MultiFactorAuthToken = Request.Form["MultiFactorAuthToken"],
                QrCodeSetupImageUrl = Request.Form["QrCodeSetupImageUrl"],
                ManualEntryKey = Request.Form["ManualEntryKey"],
                MultiFactorRequired = !string.IsNullOrEmpty(Request.Form["QrCodeSetupImageUrl"].FirstOrDefault()),
                ErrorMessage = errorMessage
            });
        }
    }
}
