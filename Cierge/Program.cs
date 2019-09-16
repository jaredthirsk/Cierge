using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Core;
using OpenIddict.Mvc;
using OpenIddict.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace Cierge
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var host = BuildWebHost(args);

            // Don't initialise database if given the IgnoreInitDb argument
            var ignoreInitDb = args.FirstOrDefault(a => a.ToLower().Contains("ignoreinitdb"));
            if (ignoreInitDb == null)
            {
                using (var scope = host.Services.CreateScope())
                {
                    var services = scope.ServiceProvider;

                    try
                    {
//                        InitializeAsync(services, CancellationToken.None).GetAwaiter().GetResult();
                    }
                    catch (Exception ex)
                    {
                        var logger = services.GetRequiredService<ILogger<Program>>();
                        logger.LogError(ex, "An error occurred seeding the DB.");
                    }
                }
            }


            host.Run();
        }

        public static IWebHost BuildWebHost(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((context, config) => 
                    config.AddJsonFile("config/appsettings.json", optional: true)
                )
                //.ConfigureLogging(c =>
                //{
                //    c.AddConsole();
                //})
                .UseStartup<Startup>()
                .Build();
    }
}
