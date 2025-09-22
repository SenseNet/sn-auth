using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using SenseNetAuth.Infrastructure.Exceptions;
using SenseNetAuth.Models;
using SenseNetAuth.Models.Constants;
using SenseNetAuth.Models.Options;
using SenseNetAuth.Services;

namespace SenseNetAuth.ApiControllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(
        IAuthService authService
    )
    {
        _authService = authService;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var response = await _authService.LoginAsync(request, HttpContext.RequestAborted);
        return Ok(response);
    }

    [HttpPost("login/multi-factor")]
    public async Task<IActionResult> MultiFactorLogin([FromBody] MultiFactorLoginRequest request)
    {
        var response = await _authService.MultiFactorLoginAsync(request, HttpContext.RequestAborted);
        return Ok(response);
    }

    [HttpPost("convert-auth-token")]
    public IActionResult ConvertAuthToken([FromBody] TokenRequest tokenRequest)
    {
        var response = _authService.ConvertAuthToken(tokenRequest);
        return Ok(response);
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        if (Request.Headers.TryGetValue("Authorization", out StringValues authorizationHeader))
        {
            string token = ExtractBearerToken(authorizationHeader);

            if (!string.IsNullOrEmpty(token))
                _authService.Logout(token);
        }

        return Ok();
    }

    [HttpDelete("remember-me")]
    public IActionResult DeleteRememberMeToken([FromBody] TokenRequest tokenRequest)
    {
        _authService.DeleteRememberMeToken(tokenRequest.Token);
        return Ok();
    }

    [HttpGet("validate-token")]
    public IActionResult ValidateToken()
    {
        if (Request.Headers.TryGetValue("Authorization", out StringValues authorizationHeader))
        {
            string token = ExtractBearerToken(authorizationHeader);

            if (!string.IsNullOrEmpty(token))
            {
                var response = _authService.ValidateToken(token);

                if (response)
                    return Ok(true);
            }
                
        }
        throw new UnauthorizedException(ResponseMessages.Unauthorized);
    }

    [HttpPost("refresh-token")]
    public IActionResult RefreshToken([FromBody] TokenRequest tokenRequest)
    {
        var response = _authService.RefreshToken(tokenRequest.Token);
        return Ok(response);
    }

    [HttpPost("registration")]
    public async Task<IActionResult> Registration([FromBody] RegistrationRequest registrationRequest)
    {
        var result = await _authService.RegisterAsync(registrationRequest, HttpContext.RequestAborted);
        return Ok(result);
    }

    [HttpPost("forgotten-password")]
    public async Task<IActionResult> ForgottenPassword([FromBody] ForgottenPasswordRequest forgottenPasswordRequest)
    {
        await _authService.ForgottenPasswordAsync(forgottenPasswordRequest, HttpContext.RequestAborted);
        return Ok();
    }

    [HttpPost("password-recovery")]
    public async Task<IActionResult> PasswordRecovery([FromBody] PasswordRecoveryRequest passwordRecoveryRequest)
    {
        await _authService.PasswordRecoveryAsync(passwordRecoveryRequest, HttpContext.RequestAborted);
        return Ok();
    }
    
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest changePasswordRequest)
    {
        Request.Headers.TryGetValue("Authorization", out StringValues authorizationHeader);
        string token = ExtractBearerToken(authorizationHeader);

        await _authService.ChangePasswordAsync(token, changePasswordRequest, HttpContext.RequestAborted);
        return Ok();
    }

    private string ExtractBearerToken(string authorizationHeader)
    {
        if (authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return authorizationHeader["Bearer ".Length..].Trim();

        return string.Empty;
    }
}
