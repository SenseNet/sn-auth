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
    private readonly ApplicationSettings _appSettings;

    public MultiFactorAuthController(
        IRecaptchaService recaptchaService, 
        IAuthService authService,
        IOptions<SensenetSettings> sensenetOptions,
        IOptions<ApplicationSettings> appOptions)
    {
        _recaptchaService = recaptchaService;
        _authService = authService;
        _sensenetSettings = sensenetOptions.Value;
        _appSettings = appOptions.Value;
    }

    [HttpPost("multiFactorAuth")]
    public async Task<IActionResult> PostTwoFactorAuth()
    {
        var flow = ExternalLoginFlow.FromForm(Request.Form);
        if (!flow.IsValid(_appSettings.AllowedHosts))
            return BadRequest("Invalid login callback");
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
                    SiteUrl = flow.RedirectUrl
                }, HttpContext.RequestAborted, false);

                if (response != null)
                    return Redirect(flow.CallbackUrl(response));
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
            return View("~/Views/Login/Index.cshtml", flow.CopyTo(new LoginViewModel
            {
                RepositoryUrl = _sensenetSettings.Repository.Url,
                ErrorMessage = "Login expired. Please sign in again."
            }));
        }
        else
        {
            return View("Index", flow.CopyTo(new MultiFactorViewModel
            {
                RepositoryUrl = _sensenetSettings.Repository.Url,
                MultiFactorAuthToken = Request.Form["MultiFactorAuthToken"],
                QrCodeSetupImageUrl = Request.Form["QrCodeSetupImageUrl"],
                ManualEntryKey = Request.Form["ManualEntryKey"],
                MultiFactorRequired = !string.IsNullOrEmpty(Request.Form["QrCodeSetupImageUrl"].FirstOrDefault()),
                ErrorMessage = errorMessage
            }));
        }
    }
}
