using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.WebUtilities;
using SenseNetAuth.Infrastructure.Exceptions;
using SenseNetAuth.Models.Constants;

namespace SenseNetAuth.Models;

// Stored with the temporary code (including the MFA step), never with a session.
public sealed record AuthorizationCodeBinding(string State, string CodeChallenge, string CallbackUri)
{
    public static AuthorizationCodeBinding? Create(string? state, string? challenge, string? method, string? callbackUri)
    {
        if (string.IsNullOrEmpty(state) && string.IsNullOrEmpty(challenge) && string.IsNullOrEmpty(method))
            return null; // Existing clients may still use the unbound protocol during rollout.

        if (string.IsNullOrEmpty(state) || state.Length > 512 ||
            !Regex.IsMatch(state, @"\A[A-Za-z0-9_-]{32,512}\z") || method != "S256" ||
            challenge == null || !Regex.IsMatch(challenge, @"\A[A-Za-z0-9_-]{43}\z"))
            throw new BadRequestException(ResponseMessages.InvalidAuthToken);

        return new AuthorizationCodeBinding(state, challenge, callbackUri ?? string.Empty);
    }

    public bool Matches(string? verifier)
    {
        if (verifier == null || !Regex.IsMatch(verifier, @"\A[A-Za-z0-9._~-]{43,128}\z"))
            return false;

        var challenge = WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(CodeChallenge), Encoding.ASCII.GetBytes(challenge));
    }
}
