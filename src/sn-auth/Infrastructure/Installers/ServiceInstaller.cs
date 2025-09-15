using SenseNet.Client;
using SenseNetAuth.Models.Options;
using SenseNetAuth.Services;

namespace SenseNetAuth.Infrastructure.Installers;

public static class ServiceInstaller
{
    public static IServiceCollection InstallServices(this IServiceCollection services)
    {
        services.AddSingleton<IAuthService, AuthService>();
        services.AddSingleton<IUserService, UserService>();
        services.AddSingleton<IEmailService, EmailService>();
        services.AddSingleton<IRecaptchaService, RecaptchaService>();

        return services;
    }
}
