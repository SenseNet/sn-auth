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
        IOptions<ApplicationSettings> appOptions,
        IRecaptchaService recaptchaService)
    {
        _sensenetSettings = sensenetOptions.Value;
        _regSettings = regOptions.Value;
        _appSettings = appOptions.Value;
        _authService = authService;
        _recaptchaService = recaptchaService;
    }

    [HttpGet("login")]
    public IActionResult Index([FromQuery] ExternalLoginFlow flow, [FromQuery] bool clearCookies)
    {
        var model = flow.CopyTo(new LoginViewModel
        {
            IsRegistrationEnabled = _regSettings.IsEnabled,
            IsHostInvalid = !flow.IsValid(_appSettings.AllowedHosts),
            RepositoryUrl = _sensenetSettings.Repository.Url,
        });

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
        var flow = ExternalLoginFlow.FromForm(Request.Form);
        var model = flow.CopyTo(new LoginViewModel());
        LoginResponse? response = null;
        if (!flow.IsValid(_appSettings.AllowedHosts))
        {
            model.IsHostInvalid = true;
        }
        else if (_recaptchaService.IsConfigured() && !await _recaptchaService.ValidateRecaptchaAsync(Request.Form["g-recaptcha-response"].FirstOrDefault() ?? string.Empty))
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
                    RememberMeRequested = Request.Form["RememberMe"].FirstOrDefault()?.ToLower() == "on",
                    SiteUrl = flow.RedirectUrl,
                    State = flow.State,
                    CodeChallenge = flow.CodeChallenge,
                    CodeChallengeMethod = flow.CodeChallengeMethod,
                    CallbackUri = flow.CallbackUri
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
            var mfaViewModel = flow.CopyTo(new MultiFactorViewModel
            {
                RepositoryUrl = _sensenetSettings.Repository.Url,
                ManualEntryKey = response.ManualEntryKey,
                MultiFactorAuthToken = response.MultiFactorAuthToken,
                MultiFactorRequired = response.MultiFactorRequired,
                QrCodeSetupImageUrl = response.QrCodeSetupImageUrl
            });
            return View("../MultiFactorAuth/Index", mfaViewModel);
        }
        else
        {
            return Redirect(flow.CallbackUrl(response));
        }
    }
}
