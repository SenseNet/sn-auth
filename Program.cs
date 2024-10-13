using SenseNet.Extensions.DependencyInjection;
using SenseNetAuth.Infrastructure.Installers;
using SenseNetAuth.Infrastructure.Middlewares;
using SenseNetAuth.Models.Constants;
using SenseNetAuth.Models.Options;
using Serilog;
using static SenseNetAuth.Infrastructure.Installers.ContentTypeInstaller;

namespace SenseNetAuth;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        builder.Services.AddRazorPages();
        builder.Services.InstallServices()
            .Configure<JwtSettings>(options => builder.Configuration.GetSection("JwtSettings").Bind(options))
            .Configure<RegistrationSettings>(options => builder.Configuration.GetSection("Registration").Bind(options))
            .Configure<ApplicationSettings>(options => builder.Configuration.GetSection("Application").Bind(options))
            .Configure<SensenetSettings>(options => builder.Configuration.GetSection("Sensenet").Bind(options))
            .Configure<PasswordRecoverySettings>(options => builder.Configuration.GetSection("PasswordRecovery").Bind(options))
            .Configure<EmailSettings>(options => builder.Configuration.GetSection("Email").Bind(options))
            .Configure<RecaptchaSettings>(options => builder.Configuration.GetSection("Recaptcha").Bind(options))
            .AddSenseNetClient()
            .ConfigureSenseNetRepository(Repositories.Default, repositoryOptions =>
            {
                builder.Configuration.GetSection("Sensenet:Repository").Bind(repositoryOptions);
            }, RegisterContentTypes);

        builder.Services.AddCors(options =>
        {
            options.AddPolicy("AllowSpecificOrigin",
                b => b.WithOrigins(builder.Configuration.GetSection("Application:AllowedHosts").Get<string[]>() ?? [])
                    .AllowAnyMethod()
                    .AllowAnyHeader());
        });

        var app = builder.Build();

        // Configure the HTTP request pipeline.
        if (!app.Environment.IsDevelopment())
            app.UseHsts();

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.File(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs/log.txt"), rollingInterval: RollingInterval.Day)
            .CreateLogger();

        app.UseMiddleware<RequestResponseLoggerMiddleware>();
        app.UseMiddleware<ExceptionHandlerMiddleware>();

        app.UseHttpsRedirection();
        app.UseStaticFiles();

        app.UseCors("AllowSpecificOrigin");

        app.UseRouting();
        app.UseEndpoints(endpoints =>
        {
            // Default route for MVC
            endpoints.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            // Enable attribute routing
            endpoints.MapControllers();
        });

        try
        {
            Log.Information("Starting up the application...");
            app.Run();
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Application start-up failed.");
        }
        finally
        {
            Log.CloseAndFlush();
        }
    }
}
