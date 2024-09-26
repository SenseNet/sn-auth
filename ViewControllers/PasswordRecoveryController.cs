using Microsoft.AspNetCore.Mvc;
using SenseNetAuth.Models.ViewModels;
using SenseNetAuth.Services;

namespace SenseNetAuth.ViewControllers;

public class PasswordRecoveryController : Controller
{
    private readonly IAuthService _authService;
    private readonly IRecaptchaService _recaptchaService;

    public PasswordRecoveryController(
        IAuthService authService,
        IRecaptchaService recaptchaService
        )
    {
        _authService = authService;
        _recaptchaService = recaptchaService;
    }

    [HttpGet("passwordRecovery")]
    public IActionResult Index([FromQuery] string token, [FromQuery] string redirectUrl, [FromQuery] string callbackUri)
    {
        return View("Index", new PasswordRecoveryViewModel
        {
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
        else if (!await _recaptchaService.ValidateRecaptchaAsync(Request.Form["g-recaptcha-response"].FirstOrDefault() ?? string.Empty))
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
