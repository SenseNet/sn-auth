using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SenseNetAuth.Models;
using SenseNetAuth.Models.Options;
using SenseNetAuth.Models.ViewModels;
using SenseNetAuth.Pages;
using SenseNetAuth.Services;

namespace SenseNetAuth.ViewControllers;

public class LoginController : Controller
{
    private readonly IAuthService _authService;
    private readonly IRecaptchaService _recaptchaService;

    private readonly SensenetSettings _sensenetSettings;
    private readonly RegistrationSettings _regSettings;
    private readonly ApplicationSettings _appSettings;

    public LoginController(
        IAuthService authService,

        IOptions<SensenetSettings> sensenetOptions,
        IOptions<RegistrationSettings> regOptions,
        IOptions<ApplicationSettings> appOptions
,
        IRecaptchaService recaptchaService)
    {
        _sensenetSettings = sensenetOptions.Value;
        _regSettings = regOptions.Value;
        _appSettings = appOptions.Value;
        _authService = authService;
        _recaptchaService = recaptchaService;
    }

    [HttpGet("login")]
    public IActionResult Index([FromQuery] string redirectUrl, [FromQuery] string callbackUri, [FromQuery] bool clearCookies)
    {
        var model = new LoginViewModel
        {
            IsRegistrationEnabled = _regSettings.IsEnabled,
            RedirectUrl = redirectUrl,
            CallbackUri = callbackUri,
            IsHostInvalid = !_appSettings.AllowedHosts.Contains(redirectUrl),
        };

        if (clearCookies && !string.IsNullOrEmpty(HttpContext.Request.Cookies["RememberMeToken"]))
        {
            _authService.DeleteRememberMeToken(HttpContext.Request.Cookies["RememberMeToken"]);
            HttpContext.Response.Cookies.Delete("RememberMeToken");
            HttpContext.Response.Cookies.Delete("RememberMeLoginName");
        }
        else
        {
            model.IsRememberMeSet = !string.IsNullOrEmpty(HttpContext.Request.Cookies["RememberMeToken"]);
            model.RememberMeLoginName = HttpContext.Request.Cookies["RememberMeLoginName"] ?? string.Empty;
        }

        return View("Index", model);
    }

    [HttpPost("login")]
    public async Task<IActionResult> PostLogin()
    {
        var model = new LoginViewModel();
        LoginResponse? response = null;
        if (!Request.Form.TryGetValue("RedirectUrl", out var redirectUrl) || !_appSettings.AllowedHosts.Contains(redirectUrl.FirstOrDefault()))
        {
            model.IsHostInvalid = true;
        }
        else if (!await _recaptchaService.ValidateRecaptchaAsync(Request.Form["g-recaptcha-response"].FirstOrDefault() ?? string.Empty))
        {
            model.ErrorMessage = "Invalid ReCaptcha";
        }
        else
        {
            try
            {
                var request = new LoginRequest
                {
                    Password = Request.Form["Password"].FirstOrDefault() ?? string.Empty,
                    LoginName = Request.Form["LoginName"].FirstOrDefault() ?? string.Empty,
                    RememberMeToken = HttpContext.Request.Cookies["RememberMeToken"] ?? string.Empty,
                    RememberMeRequested = Request.Form["RememberMe"].FirstOrDefault()?.ToLower() == "on"
                };
                response = await _authService.AuthenticateAsync(request, HttpContext.RequestAborted);
            }
            catch
            {
                model.ErrorMessage = "Invalid credentials";
            }
        }
        
        if (!string.IsNullOrEmpty(model.ErrorMessage) || model.IsHostInvalid)
        {
            model.IsRegistrationEnabled = _regSettings.IsEnabled;
            model.RedirectUrl = redirectUrl;
            model.CallbackUri = Request.Form["CallbackUri"].FirstOrDefault() ?? string.Empty;
            model.RepositoryUrl = _sensenetSettings.Repository.Url;
            model.IsRememberMeSet = !string.IsNullOrEmpty(HttpContext.Request.Cookies["RememberMeToken"]);
            model.RememberMeLoginName = HttpContext.Request.Cookies["RememberMeLoginName"] ?? string.Empty;
            return View("Index", model);
        }

        if (response?.RememberMeDetails != null)
        {
            HttpContext.Response.Cookies.Append("RememberMeToken", response.RememberMeDetails.RememberMeToken);
            HttpContext.Response.Cookies.Append("RememberMeLoginName", response.RememberMeDetails.LoginName);
        } 
        
        if (response.MultiFactorRequired)
        {
            var mfaViewModel = new MultiFactorViewModel
            {
                RedirectUrl = redirectUrl,
                CallbackUri = Request.Form["CallbackUri"].FirstOrDefault() ?? string.Empty,
                ManualEntryKey = response.ManualEntryKey,
                MultiFactorAuthToken = response.MultiFactorAuthToken,
                MultiFactorRequired = response.MultiFactorRequired,
                QrCodeSetupImageUrl = response.QrCodeSetupImageUrl
            };
            return View("../MultiFactorAuth/Index", mfaViewModel);
        }
        else
        {
            return Redirect($"{new Uri(new Uri(redirectUrl), Request.Form["CallbackUri"])}?auth_code={response.AuthToken}");
        }
    }
}
