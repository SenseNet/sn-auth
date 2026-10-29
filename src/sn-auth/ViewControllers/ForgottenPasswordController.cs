using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SenseNetAuth.Models.Options;
using SenseNetAuth.Models.ViewModels;
using SenseNetAuth.Services;

namespace SenseNetAuth.ViewControllers;

public class ForgottenPasswordController : Controller
{
    private readonly IAuthService _authService;
    private readonly IRecaptchaService _recaptchaService;

    private readonly SensenetSettings _sensenetSettings;
    private readonly RegistrationSettings _regSettings;
    private readonly ApplicationSettings _appSettings;

    public ForgottenPasswordController(
        IAuthService authService,
        IRecaptchaService recaptchaService,

        IOptions<SensenetSettings> sensenetOptions,
        IOptions<RegistrationSettings> regOptions,
        IOptions<ApplicationSettings> appOptions
        )
    {
        _sensenetSettings = sensenetOptions.Value;
        _regSettings = regOptions.Value;
        _appSettings = appOptions.Value;
        _authService = authService;
        _recaptchaService = recaptchaService;
    }

    [HttpGet("forgottenPassword")]
    public IActionResult Index([FromQuery] ExternalLoginFlow flow)
    {
        var model = flow.CopyTo(new ForgottenPasswordViewModel
        {
            RepositoryUrl = _sensenetSettings.Repository.Url,
        });

        return View("Index", model);
    }

    [HttpPost("forgottenPassword")]
    public async Task<IActionResult> PostForgottenPassword()
    {
        var flow = ExternalLoginFlow.FromForm(Request.Form);
        var model = flow.CopyTo(new ForgottenPasswordViewModel());
        if (_recaptchaService.IsConfigured() && !await _recaptchaService.ValidateRecaptchaAsync(Request.Form["g-recaptcha-response"].FirstOrDefault() ?? string.Empty))
        {
            model.ErrorMessage = "Invalid ReCaptcha";
        }
        else
        {
            try
            {
                var uri = flow.QueryString.TrimStart('?');
                await _authService.ForgottenPasswordAsync(new Models.ForgottenPasswordRequest
                {
                    Email = Request.Form["Email"]
                }, uri, HttpContext.RequestAborted);
            }
            catch { }
        }

        model.RepositoryUrl = _sensenetSettings.Repository.Url;
        if (string.IsNullOrEmpty(model.ErrorMessage))
            model.SuccessMessage = "Email sent";

        return View("Index", model);
    }
}
