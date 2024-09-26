using SenseNet.Client;

namespace SenseNetAuth.Models;

public class UserDetails
{
    public int Id { get; set; }
    public string Path { get; set; } = string.Empty;
    public string LoginName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty; 
    public Avatar Avatar { get; set; }
}

public class Avatar
{
    public string Url { get; set; } = string.Empty;
}
