using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SenseNetAuth.Models.Options;
using SenseNetAuth.Models.ViewModels;
using SenseNetAuth.Services;

namespace SenseNetAuth.ViewControllers;

public class PasswordRecoveryController : Controller
{
    private readonly IAuthService _authService;
    private readonly IRecaptchaService _recaptchaService;
    private readonly SensenetSettings _sensenetSettings;

    public PasswordRecoveryController(
        IAuthService authService,
        IRecaptchaService recaptchaService,
        IOptions<SensenetSettings> sensenetOptions
        )
    {
        _authService = authService;
        _recaptchaService = recaptchaService;
        _sensenetSettings = sensenetOptions.Value;
    }

    [HttpGet("passwordRecovery")]
    public IActionResult Index([FromQuery] string token, [FromQuery] string redirectUrl, [FromQuery] string callbackUri)
    {
        return View("Index", new PasswordRecoveryViewModel
        {
            RepositoryUrl = _sensenetSettings.Repository.Url,
            CallbackUri = callbackUri,
            RedirectUrl = redirectUrl,
            RecoveryToken = token
        });
    }

    [HttpPost("passwordRecovery")]
    public async Task<IActionResult> PostRecoveryToken()
    {
        var model = new PasswordRecoveryViewModel();
        if (Request.Form["Password"] != Request.Form["ConfirmPassword"])
        {
            model.ErrorMessage = "Passwords mismatch";
        }
        else if (_recaptchaService.IsConfigured() && !await _recaptchaService.ValidateRecaptchaAsync(Request.Form["g-recaptcha-response"].FirstOrDefault() ?? string.Empty))
        {
            model.ErrorMessage = "Invalid ReCaptcha";
        }
        else
        {
            try
            {
                await _authService.PasswordRecoveryAsync(new Models.PasswordRecoveryRequest
                {
                    Password = Request.Form["Password"],
                    Token = Request.Form["Token"]
                }, HttpContext.RequestAborted);
            }
            catch
            {
                model.ErrorMessage = "Invalid recovery token";
            }
        }

        if (!string.IsNullOrEmpty(model.ErrorMessage))
        {
            model.RepositoryUrl = _sensenetSettings.Repository.Url;
            model.RedirectUrl = Request.Form["RedirectUrl"];
            model.CallbackUri = Request.Form["CallbackUri"];
            model.RecoveryToken = Request.Form["Token"];
            return View("Index", model);
        }
        else
        {
            return Redirect($"/Login?redirectUrl={Request.Form["RedirectUrl"]}&callbackUri={Request.Form["CallbackUri"]}");
        }
    }
}
