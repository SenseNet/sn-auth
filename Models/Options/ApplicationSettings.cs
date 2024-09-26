namespace SenseNetAuth.Models.Options;

public class ApplicationSettings
{
    public string Url { get; set; } = string.Empty;
    public string[] AllowedHosts { get; set; } = [];
}