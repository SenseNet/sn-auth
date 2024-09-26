namespace SenseNetAuth.Models.Options;

public class SensenetSettings
{
    public RepositorySettings Repository { get; set; }
}

public class RepositorySettings
{
    public string Url { get; set; } = string.Empty;
    public AuthtenticationSettings Authtentication { get; set; }
}

public class AuthtenticationSettings
{
    public string ApiKey { get; set; } = string.Empty;
}

