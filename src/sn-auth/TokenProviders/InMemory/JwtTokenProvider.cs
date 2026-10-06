using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SenseNetAuth.Models.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SenseNetAuth.TokenProviders.InMemory;

public class JwtTokenProvider : InMemoryTokenProvider
{
    private readonly JwtSettings _jwtSettings;

    public JwtTokenProvider(IOptions<JwtSettings> jwtSettings)
    {
        _jwtSettings = jwtSettings.Value;
    }

    public override string CreateToken(int userId, string siteUrl)
        => CreateToken(new UserInfo(userId, default, siteUrl));

    public override string CreateToken(UserInfo userInfo)
    {
        if (string.IsNullOrEmpty(userInfo.SessionId))
            userInfo = userInfo with { SessionId = Guid.NewGuid().ToString("N") };

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var expiration = new DateTimeOffset(DateTime.UtcNow.AddMinutes(_jwtSettings.TokenExpiryMinutes));
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Iss, _jwtSettings.Issuer),
            new Claim(JwtRegisteredClaimNames.Sub, userInfo.UserId.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new Claim(JwtRegisteredClaimNames.Exp, expiration.ToUnixTimeSeconds().ToString()),
            new Claim(JwtRegisteredClaimNames.AuthTime, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_jwtSettings.TokenExpiryMinutes),
            signingCredentials: credentials
        );

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

        // Retain this session's earlier access tokens until expiry so a concurrent logout
        // using the previous token still revokes the session after a refresh.
        StoreToken(tokenString, userInfo with { Expiry = expiration }, _jwtSettings.SingleSessionPerUser,
            replaceSessionTokens: false);

        return tokenString;
    }
}
