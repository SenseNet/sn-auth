using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SenseNetAuth.Infrastructure.Exceptions;
using SenseNetAuth.Models.Constants;
using SenseNetAuth.Models.Options;
using SenseNetAuth.Models.ViewModels;
using SenseNetAuth.Services;

namespace SenseNetAuth.ViewControllers;

public class RegistrationController : Controller
{
    private readonly IAuthService _authService;
    private readonly IRecaptchaService _recaptchaService;

    private readonly SensenetSettings _sensenetSettings;
    private readonly RegistrationSettings _regSettings;
    private readonly ApplicationSettings _appSettings;

    public RegistrationController(
        IAuthService authService,
        IRecaptchaService recaptchaService,

        IOptions<SensenetSettings> sensenetOptions,
        IOptions<RegistrationSettings> regOptions,
        IOptions<ApplicationSettings> appOptions
        )
    {
        _sensenetSettings = sensenetOptions.Value;
        _recaptchaService = recaptchaService;
        _regSettings = regOptions.Value;
        _appSettings = appOptions.Value;
        _authService = authService;
    }

    [HttpGet("registration")]
    public IActionResult Index([FromQuery] ExternalLoginFlow flow)
    {
        if (!_regSettings.IsEnabled)
            return Redirect($"/Login{flow.QueryString}");

        var model = flow.CopyTo(new RegistrationViewModel
        {
            IsRegistrationEnabled = true,
            RepositoryUrl = _sensenetSettings.Repository.Url
        });

        return View("Index", model);
    }

    [HttpPost("registration")]
    public async Task<IActionResult> PostRegistration()
    {
        var flow = ExternalLoginFlow.FromForm(Request.Form);
        var model = flow.CopyTo(new RegistrationViewModel());
        if (!flow.IsValid(_appSettings.AllowedHosts))
            model.IsHostInvalid = true;

        if (model.IsHostInvalid)
            model.ErrorMessage = "Invalid login callback";
        else if (Request.Form["Password"] != Request.Form["ConfirmPassword"])
            model.ErrorMessage = "Passwords mismatch";
        else if (_recaptchaService.IsConfigured() && !await _recaptchaService.ValidateRecaptchaAsync(Request.Form["g-recaptcha-response"].FirstOrDefault() ?? string.Empty))
        {
            model.ErrorMessage = "Invalid ReCaptcha";
        }
        else
        {
            try
            {
                await _authService.RegisterAsync(new Models.RegistrationRequest
                {
                    Email = Request.Form["Email"],
                    Password = Request.Form["Password"],
                    FullName = Request.Form["FullName"]
                }, HttpContext.RequestAborted);
            }
            catch (Exception ex)
            {
                if (ex is BadRequestException bre)
                {
                    if (bre.ErrorMessage == ResponseMessages.InvalidEmail)
                        model.ErrorMessage = "Invalid email format";
                    else if (bre.ErrorMessage == ResponseMessages.InvalidPassword)
                        model.ErrorMessage = "Password must contain one lower and one uppercase character and also a number";
                }
                else
                {
                    model.ErrorMessage = "Couldn't create user";
                }
            }
        }

        if (!string.IsNullOrEmpty(model.ErrorMessage) || model.IsHostInvalid)
        {
            model.IsRegistrationEnabled = true;
            model.RepositoryUrl = _sensenetSettings.Repository.Url;
            return View("Index", model);
        }
        else
        {
            var loginModel = flow.CopyTo(new LoginViewModel
            {
                IsRegistrationEnabled = true,
                RepositoryUrl = _sensenetSettings.Repository.Url,
                IsHostInvalid = model.IsHostInvalid,
                SuccessMessage = "Successful registration"
            });

            return View("../Login/Index", loginModel);
        }
    }
}
