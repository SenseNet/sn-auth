using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using SenseNetAuth.Infrastructure.Exceptions;
using SenseNetAuth.Models.Constants;
using SenseNetAuth.Services;

namespace SenseNetAuth.ApiControllers;

[Route("api/[controller]")]
[ApiController]
public class UserController : ControllerBase
{
    private readonly IAuthService _authService;

    public UserController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpGet]
    public async Task<IActionResult> GetUserDetails()
    {
        if (Request.Headers.TryGetValue("Authorization", out StringValues authorizationHeader))
        {
            string token = ExtractBearerToken(authorizationHeader);

            if (!string.IsNullOrEmpty(token))
                return Ok(await _authService.GetUserDetailsAsync(token, HttpContext.RequestAborted));
        }

        throw new UnauthorizedException(ResponseMessages.Unauthorized);
    }

    private string ExtractBearerToken(string authorizationHeader)
    {
        if (authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return authorizationHeader["Bearer ".Length..].Trim();

        return string.Empty;
    }
}
