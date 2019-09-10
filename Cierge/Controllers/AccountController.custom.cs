using Cierge.Data;
using Cierge.Models;
using Cierge.Models.AccountViewModels;
using Cierge.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Cierge.Controllers
{
    public enum RequestLoginCodeResult
    {
        ModelInvalid,
        ReachedMaxLoginsAllowed,
        EmailAlreadyAssociatedWithAccount,
        SentEmailCode,
    }

    public class LoginResult
    {
        public RequestLoginCodeResult Kind { get; set; }
        public string Email { get; set; }
        public string Purpose { get; set; }

        public static implicit operator LoginResult(RequestLoginCodeResult kind) => new LoginResult { Kind = kind };
    }

    public partial class AccountController
    {
        public async Task<LoginResult> _Login(LoginViewModel model, string returnUrl = null)
        {
            if (!ModelState.IsValid)
                return RequestLoginCodeResult.ModelInvalid;

            AuthOperation attemptedOperation;

            ApplicationUser userToSignTokenWith;

            var email = _userManager.NormalizeKey(model.Email);

            var userWithConfirmedEmail = await _userManager.FindByLoginAsync("Email", email);
            var userCurrentlySignedIn = await _userManager.GetUserAsync(User);

            if (userCurrentlySignedIn == null) // No locally signed-in user (trying to register or login)
            {
                // Clear the existing external cookie to ensure a clean login process
                await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

                if (userWithConfirmedEmail == null) // Email not associated with any other accounts (trying to register)
                {
                    userToSignTokenWith = new ApplicationUser()
                    {
                        Id = email,
                        Email = email,
                        SecurityStamp = TemporarySecurityStamp
                    };

                    attemptedOperation = AuthOperation.Registering;
                }
                else // Email associated with an account (trying to login)
                {
                    userToSignTokenWith = userWithConfirmedEmail;
                    attemptedOperation = AuthOperation.LoggingIn;
                }
            }
            else // A user is currently locally signed-in (trying to add email)
            {
                userToSignTokenWith = userCurrentlySignedIn;

                if (userWithConfirmedEmail == null) // Email not associated with any other accounts (trying to add a novel email)
                {
                    // Check to see if user reached max logins
                    if (DidReachMaxLoginsAllowed(userCurrentlySignedIn))
                    {
                        return RequestLoginCodeResult.ReachedMaxLoginsAllowed;
                    }

                    attemptedOperation = AuthOperation.AddingNovelEmail;
                }
                else // Email associated with another user's account
                {
                    if (userWithConfirmedEmail.Id == userCurrentlySignedIn.Id) // Email already added to user's account
                    {
                        return RequestLoginCodeResult.EmailAlreadyAssociatedWithAccount;
                    }
                    else // Email associated with another account that's not the user's
                    {
                        attemptedOperation = AuthOperation.AddingOtherUserEmail;
                    }
                }
            }

            var token = "";
            var purpose = "";

            switch (attemptedOperation)
            {
                case AuthOperation.AddingOtherUserEmail:
                    purpose = "AddEmail";
                    break;
                case AuthOperation.AddingNovelEmail:
                    purpose = "AddEmail";
                    token = await _userManager.GenerateUserTokenAsync(userToSignTokenWith, "Email", purpose);
                    break;
                case AuthOperation.Registering:
                case AuthOperation.LoggingIn:
                    purpose = "RegisterOrLogin";
                    token = await _userManager.GenerateUserTokenAsync(userToSignTokenWith, "Email", purpose);
                    break;
            }

            // Add a space every 3 characters for readability
            token = String.Concat(token.SelectMany((c, i)
                                            => (i + 1) % 3 == 0 ? $"{c} " : $"{c}")).Trim();

            var callbackUrl = Url.TokenInputLink(Request.Scheme,
                new TokenInputViewModel
                {
                    Token = token,
                    RememberMe = model.RememberMe,
                    ReturnUrl = returnUrl,
                    Email = email,
                    Purpose = purpose
                });

            // Will not wait for email to be sent
#pragma warning disable CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
            _emailSender.SendTokenAsync(email, attemptedOperation, callbackUrl, token);
#pragma warning restore CS4014

            return new LoginResult
            {
                Kind = RequestLoginCodeResult.SentEmailCode,
                Email = email,
                Purpose = purpose,
            };
        }

        /// <summary>
        /// Similar to Login, but designed to be used as an API, so it won't return Views.
        /// </summary>
        /// <param name="model"></param>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [HttpPost]
        [AllowAnonymous]
        //[ValidateAntiForgeryToken] not present, so that a SPA can invoke this from another domain
        public async Task<IActionResult> RequestLoginCode(LoginViewModel model, string returnUrl = null)
        {
            var result = await _Login(model, returnUrl);

            switch (result.Kind)
            {
                case RequestLoginCodeResult.ModelInvalid:
                    return BadRequest();
                case RequestLoginCodeResult.ReachedMaxLoginsAllowed:
                    return new ContentResult
                    {
                        Content = "Reached Max Logins Allowed",
                        StatusCode = 429,
                    };
                case RequestLoginCodeResult.EmailAlreadyAssociatedWithAccount:
                    return new ContentResult
                    {
                        Content = "Email already associated with account",
                        StatusCode = 200,
                    };
                case RequestLoginCodeResult.SentEmailCode:
                    return new ContentResult
                    {
                        Content = $"Sent code to {result.Email} (purpose: {result.Purpose})" ,
                        StatusCode = 201,
                    };
                default:
                    throw new NotImplementedException();
            }
        }
    }
}
