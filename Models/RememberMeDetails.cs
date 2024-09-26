namespace SenseNetAuth.Models;

public class RememberMeDetails
{
    public string RememberMeToken { get; set; } = string.Empty;
    public string LoginName { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
}
