using IntegrationTests.Fakes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SenseNetAuth.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IntegrationTests
{
    // Use the Program class from your main app
    public class SensenetAuthApplicationFactory : WebApplicationFactory<SenseNetAuth.Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureAppConfiguration((context, configBuilder) =>
            {
                var path = Path.Combine(AppContext.BaseDirectory, "testSensenetAuthSettings.json");
                configBuilder.AddJsonFile(path, optional: false, reloadOnChange: true);
            });

            builder.ConfigureServices(services =>
            {
                // Remove existing IUserService registrations
                var descriptor = services.SingleOrDefault(
                    d => d.ServiceType == typeof(IUserService));
                if (descriptor != null)
                {
                    services.Remove(descriptor);
                }

                // Register TestUserService as IUserService
                // To use Sensenet as a user service, set the URL and API key in testSensenetAuthSettings.json.
                services.AddSingleton<IUserService, FakeUserService>();
            });
        }
    }
}