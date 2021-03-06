﻿using Cierge.Data;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Cierge
{
    public static class StringExtensions
    {
        public static IEnumerable<string> ToStringArray(this string itemsAsString)
        {
            if (string.IsNullOrWhiteSpace(itemsAsString)) return Enumerable.Empty<string>();
            return itemsAsString.Split(' ');
        }

        public static string ReverseDomain(this string domain) => domain.Split('.').Reverse().Aggregate((x, y) => $"{x}.{y}");
    }
    public partial class Startup
    {
        #region Parameters

        public string Domain => Configuration["OpenIddict:Domain"];
        //public string ReversedDomain => Configuration["OpenIddict:Domain"].ReverseDomain();

        public IEnumerable<string> Subdomains => Configuration["OpenIddict:Subdomains"].ToStringArray().Select(item => item == "null" ? null : item) ?? DefaultSubdomains;
        public string SubdomainsString => Subdomains.Aggregate((x, y) => $"{x}, {y}");

        public IEnumerable<string> DefaultSubdomains { get; } = new string[] { null, "dev", "test" };
        private string ScopeForSubdomain(string subdomain = "") => ((subdomain ?? "").Contains("test") ? "test." : "") + Domain;

        public string CallbackUriPath => Configuration["OpenIddict:CallbackUriPath"] ?? "/oidc/callback";

        #endregion

        public bool DeleteExistingApplications
        {
            get
            {
                if (bool.TryParse(Configuration["OpenIddict:DeleteExistingApplications"], out bool result)) return result;
                return true;
            }
        }

        private async Task AddApplicationIfMissing(OpenIddictApplicationManager<OpenIddictApplication> manager, string subdomain = null)
        {
            //var subdomainSuffix = string.IsNullOrEmpty(subdomain) ? "" : ("." + subdomain);
            var subdomainPrefix = string.IsNullOrEmpty(subdomain) ? "" : (subdomain + ".");
            var callbackUri = $"https://{subdomainPrefix}{Domain}{CallbackUriPath}";
            var fullDomain = subdomainPrefix + Domain;
            var scope = ScopeForSubdomain(subdomain);

            var clientId = subdomainPrefix + Domain;

            var existing = await manager.FindByClientIdAsync(clientId);
            if (existing == null || DeleteExistingApplications)
            {
                if (existing != null) await manager.DeleteAsync(existing);

                logger.LogInformation($"Application at '{fullDomain}' with client id '{clientId}' being configured for scope '{scope}' with callback Uri: '{callbackUri}'");

                var descriptor = new OpenIddictApplicationDescriptor
                {
                    ClientId = clientId,
                    
                    DisplayName = fullDomain, // ENH: Make configurable
                    PostLogoutRedirectUris = { new Uri($"https://{subdomainPrefix}{Domain}/logged-out") },
                    RedirectUris = { new Uri(callbackUri) },

                    Permissions =
                            {
                                OpenIddictConstants.Permissions.Endpoints.Authorization,
                                OpenIddictConstants.Permissions.Endpoints.Logout,
                                OpenIddictConstants.Permissions.Endpoints.Token,
                                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                                OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.Email,
                                OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OpenId,
                                OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.Profile,
                                OpenIddictConstants.Permissions.Prefixes.Scope + scope,
                            }
                };
                await manager.CreateAsync(descriptor);
            }
            else
            {
                logger.LogInformation($"Application at '{fullDomain}' already configured (scope '{scope}')");
            }
        }

        private async Task InitializeAsync(IServiceProvider services)
        {
            logger.LogInformation($"Initializing with domain '{Domain}' and subdomains '{SubdomainsString}'");

            using (var serviceScope = services.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                var context = serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

                await context.Database.EnsureCreatedAsync();

                await CreateApplicationsAsync();
                await CreateScopesAsync();

                async Task CreateApplicationsAsync()
                {
                    var manager = serviceScope.ServiceProvider.GetRequiredService<OpenIddictApplicationManager<OpenIddictApplication>>();

                    foreach (var subdomain in Subdomains)
                    {
                        await AddApplicationIfMissing(manager, subdomain);
                    }
                }

                async Task CreateScopesAsync()
                {
                    var manager = serviceScope.ServiceProvider.GetRequiredService<OpenIddictScopeManager<OpenIddictScope>>();

                    foreach (var scope in Subdomains.Select(subdomain => ScopeForSubdomain(subdomain)).Distinct())
                    {
                        if (await manager.FindByNameAsync(scope) == null)
                        {
                            await manager.CreateAsync(new OpenIddictScopeDescriptor
                            {
                                Name = scope,
                                Resources = { scope },
                            });
                            logger.LogInformation($"Scope of '{scope}' registered");
                        }
                        else
                        {
                            logger.LogInformation($"Scope of '{scope}' already registered");
                        }
                    }
                }

                // Create roles
                //var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
                //string[] roleNames = { "Administrator" };
                //foreach (var roleName in roleNames)
                //{
                //    if (!await roleManager.RoleExistsAsync(roleName))
                //    {
                //        await roleManager.CreateAsync(new IdentityRole(roleName));
                //    }
                //}
            }
        }
    }
}
