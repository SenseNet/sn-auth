using SenseNet.Client;

namespace SenseNetAuth.Infrastructure.Installers;

public static class ContentTypeInstaller
{
    public static void RegisterContentTypes(RegisteredContentTypes types)
    {
        types.Add<User>();
    }
}
