namespace SenseNetAuth.Models;

public class MultiFactorLoginRequest
{
    public string MultiFactorAuthToken { get; set; } = string.Empty;
    public string MultiFactorCode { get; set; } = string.Empty;
}
