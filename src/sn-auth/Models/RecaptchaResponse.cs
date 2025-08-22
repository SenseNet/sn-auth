namespace SenseNetAuth.Models;

public class RecaptchaResponse
{
    public bool Success { get; set; }

    public float Score { get; set; }

    public string Action { get; set; } = string.Empty;

    public DateTime ChallengeTimestamp { get; set; }

    public string Hostname { get; set; } = string.Empty;

    public List<string> ErrorCodes { get; set; } = [];
}
