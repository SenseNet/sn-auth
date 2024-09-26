using Microsoft.AspNetCore.Mvc;
using SenseNetAuth.Infrastructure.Exceptions;
using SenseNetAuth.Models.Constants;
using SenseNetAuth.Models.ViewModels;
using SenseNetAuth.Services;

namespace SenseNetAuth.ViewControllers;

public class MultiFactorAuthController : Controller
{
    private readonly IAuthService _authService;
    private readonly IRecaptchaService _recaptchaService;

    public MultiFactorAuthController(IRecaptchaService recaptchaService, IAuthService authService)
    {
        _recaptchaService = recaptchaService;
        _authService = authService;
    }

    [HttpPost("multiFactorAuth")]
    public async Task<IActionResult> PostTwoFactorAuth()
    {
        var errorMessage = string.Empty;
        var isMultiFactorTokenExpired = false;
        if (!await _recaptchaService.ValidateRecaptchaAsync(Request.Form["g-recaptcha-response"].FirstOrDefault() ?? string.Empty))
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
                    MultiFactorCode = Request.Form["MultiFactorCode"]
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
