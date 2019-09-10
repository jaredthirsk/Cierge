using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Cierge.Data;
using Cierge.Filters;
using Cierge.Models;
using Cierge.Models.AccountViewModels;
using Cierge.Models.HomeViewModels;
using Cierge.Services;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Text.RegularExpressions;

namespace Cierge.Controllers
{
    [Authorize]
    [Route("[controller]/[action]")]
    public partial class AccountController : Controller
    {
        private readonly EventsService _events;
        private readonly NoticeService _notice;
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ApplicationDbContext _context;
        private readonly IEmailSender _emailSender;
        private readonly ILogger _logger;

        public AccountController(
            EventsService events,
            NoticeService notice,
            IConfiguration configuration,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ApplicationDbContext context,
            IEmailSender emailSender,
            ILogger<AccountController> logger)
        {
            _events = events;
            _notice = notice;
            _configuration = configuration;
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
            _emailSender = emailSender;
            _logger = logger;


        }

        // This is used to sign the TOTP for registering users.
        // If this value is changed (ie. server restarted), all
        // registration TOTPs will be invalidated.
        // TODO: maybe make this a more permamnent value for statelessness?
        private string TemporarySecurityStamp = new Guid().ToString();

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            var user = await _userManager.GetUserAsync(User);

            var model = new LoginViewModel();

            if (user != null)
            {
                model.DidReachMaxLoginsAllowed = DidReachMaxLoginsAllowed(user);
                model.MaxLoginsAllowed = MaxLoginsAllowed;
            }

            return View(model);
        }


        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            var result = await _Login(model, returnUrl);
            switch (result.Kind)
            {
                case RequestLoginCodeResult.ModelInvalid:
                    return View(model);
                case RequestLoginCodeResult.ReachedMaxLoginsAllowed:
                    return View(nameof(Login), new LoginViewModel
                    {
                        MaxLoginsAllowed = MaxLoginsAllowed,
                        DidReachMaxLoginsAllowed = true
                    });
                case RequestLoginCodeResult.EmailAlreadyAssociatedWithAccount:
                    _notice.AddErrors(ModelState, "This email is already in your account.");
                    return View(model);
                case RequestLoginCodeResult.SentEmailCode:
                    return View(nameof(TokenInput),
                        new TokenInputViewModel
                        {
                            RememberMe = model.RememberMe,
                            ReturnUrl = returnUrl,
                            Email = result.Email,
                            Purpose = result.Purpose
                        });
                default:
                    throw new NotImplementedException();
            }
        }


        [HttpGet]
        [AllowAnonymous]
        public IActionResult TokenInput(TokenInputViewModel model)
        {   
            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        //[ValidateAntiForgeryToken]
        [ActionName(nameof(AccountController.TokenInput))]
        [ServiceFilter(typeof(ValidateRecaptchaAttribute))]
        public async Task<IActionResult> SubmitTokenInput(TokenInputViewModel model)
        {
            if (!ModelState.IsValid ||
                String.IsNullOrWhiteSpace(model.Email) ||
                String.IsNullOrWhiteSpace(model.Purpose) ||
                String.IsNullOrWhiteSpace(model.Token))
            {
                return View(model);
            }

            var email = _userManager.NormalizeKey(model.Email);
            model.Token = model.Token.Replace(" ", "");
            
            var userWithConfirmedEmail = await _userManager.FindByLoginAsync("Email", email);
            var userCurrentlySignedIn = await _userManager.GetUserAsync(User);    
            var userEmpty = new ApplicationUser()
            {
                Id = email,
                Email = email,
                SecurityStamp = TemporarySecurityStamp
            };

            var isTokenValid = false;

            if (model.Purpose == "RegisterOrLogin") // Trying to register or login
            {
                await _signInManager.SignOutAsync();

                isTokenValid = await _userManager.VerifyUserTokenAsync(
                    userWithConfirmedEmail  // Case: logging-in
                    ?? userEmpty,           // Case: registering,
                    "Email", model.Purpose, model.Token);
            }
            else // Trying to add email
            {
                if (userCurrentlySignedIn == null) // If the user is not signed in, prompt them to, with the return url leading back here
                    return RedirectToAction(nameof(Login), new
                    {
                        returnUrl = Request.Path + Request.QueryString
                    });

                isTokenValid = await _userManager.VerifyUserTokenAsync(
                    userCurrentlySignedIn,
                    "Email", model.Purpose, model.Token);
            }

            if (!isTokenValid)
            {
                _notice.AddErrors(ModelState, "Error validating code, it might have expired. Please try again!");
                return View(model);
            }

            // Invalidates all tokens for user when trying to login or add login
            // Note: this also invalidates any attempts to add more logins than allowed
            if ((userCurrentlySignedIn ?? userWithConfirmedEmail) != null)
            {
                var updateSecStampResult = await _userManager.UpdateSecurityStampAsync(userCurrentlySignedIn ?? userWithConfirmedEmail);
                if (!updateSecStampResult.Succeeded)
                {
                    _notice.AddErrors(ModelState);
                    return View(model);
                }
            }

            // Valid {token + email (user) + purpose} supplied

            if (model.Purpose == "RegisterOrLogin") // Trying to register or login
            {
                if (userWithConfirmedEmail == null) // Success trying to register
                {
                    var token = await _userManager.GenerateUserTokenAsync(userEmpty, "Default", "Register");

                    return View(nameof(Register), new RegisterViewModel
                    {
                        RememberMe = model.RememberMe,
                        Email = email,
                        UserName = GenerateUserName(email),
                        Token = token,
                        ReturnUrl = model.ReturnUrl
                    });
                }
                else // Success trying to login
                {
                    await _events.AddEvent(AuthEventType.Login, JsonConvert.SerializeObject(new
                    {
                        LoginProvider = "Email",
                        ProviderKey = model.Email
                    }), userWithConfirmedEmail);

                    await _signInManager.SignInAsync(userWithConfirmedEmail, isPersistent: model.RememberMe);
                }
            }
            else // Trying to add email
            {
                var userWithConfirmedEmailToAdd = await _userManager.FindByLoginAsync("Email", email);
                
                if (userWithConfirmedEmailToAdd == null) // Email to be added never seen before, add email to userCurrentlySignedIn
                {

                    var addLoginResult = await _userManager.AddLoginAsync(userCurrentlySignedIn, 
                        new UserLoginInfo("Email", email, "Email"));

                    if (!addLoginResult.Succeeded)
                    {
                        _notice.AddErrors(ModelState, addLoginResult);
                        return View(model);
                    }

                    userCurrentlySignedIn.Email = email;
                    userCurrentlySignedIn.EmailConfirmed = true;
                    var updateUserResult = await _userManager.UpdateAsync(userCurrentlySignedIn);

                    if (!updateUserResult.Succeeded)
                    {
                        _notice.AddErrors(ModelState, updateUserResult);
                        return View(model);
                    }

                    await _events.AddEvent(AuthEventType.AddLogin, JsonConvert.SerializeObject(new
                    {
                        LoginProvider = "Email",
                        ProviderKey = model.Email
                    }), userCurrentlySignedIn);
                    
                }
                else // Email to be added is in use
                {
                    // Note: this area is unlikely to be reached since security stamp is changed once a login is added
                    if (userWithConfirmedEmailToAdd.Id == userCurrentlySignedIn.Id) // Email is already in user's account 
                    {
                        _notice.AddErrors(ModelState, "This email is already in your account.");
                        return View(model);
                    }
                    else // Email associated with another account (same user since both verified!)
                    {
                        _notice.AddErrors(ModelState, "This email is in another user's account. Try logging in using that email instead.");
                        return View(model);
                    }
                }
            }

            // Success
            return RedirectToLocal(model.ReturnUrl);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginAsync(string provider, string returnUrl = null)
        {
            if (_signInManager.IsSignedIn(User))
                await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme); // Clear the existing external cookie to ensure a clean login process

            // Request a redirect to the external login provider.
            var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl, _userManager.GetUserId(User));
            return new ChallengeResult(provider, properties);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            if (remoteError != null)
                return RedirectToAction(nameof(Login));

            var info = await _signInManager.GetExternalLoginInfoAsync();

            if (info == null)
                return RedirectToAction(nameof(Login));

            var userWithExternalLogin = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
            var userCurrentlySignedIn = await _userManager.GetUserAsync(User);


            var emailFromExternalLoginProvider = _userManager.NormalizeKey(info.Principal.FindFirstValue(ClaimTypes.Email));
            var nameFromExternalLoginProvider = _userManager.NormalizeKey(info.Principal.FindFirstValue(ClaimTypes.Name));

            if (userCurrentlySignedIn == null) // No locally signed-in user (trying to register or login)
            {
                if (userWithExternalLogin != null) // User exists and attempting to login
                {
                    var externalLoginResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

                    if (externalLoginResult.Succeeded) // Success logging in
                    {
                        await _events.AddEvent(AuthEventType.Login, JsonConvert.SerializeObject(new
                        {
                            info.LoginProvider,
                            info.ProviderKey
                        }), userWithExternalLogin);

                        return RedirectToLocal(returnUrl);
                    }

                    if (externalLoginResult.IsLockedOut || externalLoginResult.IsNotAllowed)
                        return RedirectToAction(nameof(Lockout));
                }

                // TODO: what if `await _userManager.FindByLoginAsync(ANY, info.ProviderKey)` exists?
                //       ie. email of external login is already associated with full account
                //       currently, to avoid leaking profile existence, this is ignored.

                // The user does not have an account, is attempting to register
                return View(nameof(Register), new RegisterViewModel
                {
                    Email = emailFromExternalLoginProvider,
                    UserName = GenerateUserName(nameFromExternalLoginProvider),
                    ExternalLoginProviderDisplayName = info.ProviderDisplayName,
                    ReturnUrl = returnUrl
                });

            }
            else // A user is currently locally signed-in (trying to add external login)
            {

                if (userWithExternalLogin != null) // External login already in use
                {
                    if (userWithExternalLogin.Id == userCurrentlySignedIn.Id) // External login is already in user's account
                    {
                        _notice.AddErrors(ModelState, "This external login is already in your account.");
                        return View(nameof(Login));
                    }
                    else
                    {
                        _notice.AddErrors(ModelState, "This external login is in another user's account. Try loggin out then back in with that instead.");
                        return View(nameof(Login));
                    }
                }

                // Check to see if user reached max logins
                if (DidReachMaxLoginsAllowed(userCurrentlySignedIn))
                {
                    return View(nameof(Login), new LoginViewModel
                    {
                        MaxLoginsAllowed = MaxLoginsAllowed,
                        DidReachMaxLoginsAllowed = true
                    });
                }

                // If email is not confirmed then update their unconfirmed email
                if (!String.IsNullOrWhiteSpace(emailFromExternalLoginProvider) &&
                    userCurrentlySignedIn.EmailConfirmed == false)
                {
                    userCurrentlySignedIn.Email = emailFromExternalLoginProvider;
                    userCurrentlySignedIn.EmailConfirmed = false;
                }
                    
                var addLoginResult = await _userManager.AddLoginAsync(userCurrentlySignedIn, info);
                if (addLoginResult.Succeeded)
                {
                    var updateResult = await _userManager.UpdateAsync(userCurrentlySignedIn);
                    if (updateResult.Succeeded)
                    {
                        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme); // Clear the existing external cookie to ensure a clean login process

                        await _events.AddEvent(AuthEventType.AddLogin, JsonConvert.SerializeObject(new
                        {
                            info.LoginProvider,
                            info.ProviderKey
                        }), userCurrentlySignedIn);

                        return RedirectToLocal(returnUrl);
                    }
                    else
                    {
                        _notice.AddErrors(ModelState, updateResult);
                    }
                }
                else
                {
                    _notice.AddErrors(ModelState, addLoginResult);
                }

                return View(nameof(Login));
            }

        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid || 
                String.IsNullOrWhiteSpace(model.Email)) //  Note: this means that external logins not providing an email are unusable.
                return View("Register", model);

            var email = _userManager.NormalizeKey(model.Email);
            
            UserLoginInfo info = await _signInManager.GetExternalLoginInfoAsync();

            var userEmpty = new ApplicationUser()
            {
                UserName = model.UserName,
                Email = email,
                DateCreated = DateTimeOffset.UtcNow,
                SecurityStamp = TemporarySecurityStamp,

                FullName = model.FullName,
                FavColor = model.FavColor, // !! ADDING FIELDS: If you want users to input field on register
            };

            userEmpty.Email = email;

            //userEmpty.FavColor = "Red"; // !! ADDING FIELDS: If you want to set default value for all registering users

            if (info == null) // User trying to register locally
            {
                userEmpty.EmailConfirmed = true;

                var userWithConfirmedEmail = await _userManager.FindByLoginAsync("Email", email);

                userEmpty.Id = email; // Only for token verification, is set to null later
                var isTokenValid = await _userManager.VerifyUserTokenAsync(userEmpty, "Default", "Register", model.Token);

                if (isTokenValid && userWithConfirmedEmail == null) // Supplied email is verified & user does not exist
                {
                    userEmpty.Id = null;
                    info = new UserLoginInfo("Email", userEmpty.Email, "Email");
                }
                else
                {
                    _notice.AddErrors(ModelState);
                    return View(nameof(Register), model);
                }

            }
            else // User trying to register after external login
            {
                userEmpty.EmailConfirmed = false;
            }

            var createResult = await _userManager.CreateAsync(userEmpty);
            if (createResult.Succeeded)
            {
                var addLoginResult = await _userManager.AddLoginAsync(userEmpty, info);
                if (addLoginResult.Succeeded)
                {
                    var user = await _userManager.FindByNameAsync(model.UserName); // This works because usernames are unique

                    // If this is the first user ever created, make an Administrator
                    if (_userManager.Users.Count() == 1)
                    {
                        var makeAdminResult = await _userManager.AddToRoleAsync(user, "Administrator");
                    }

                    await _events.AddEvent(AuthEventType.Register, JsonConvert.SerializeObject(new
                    {
                        LoginProvider = info?.LoginProvider ?? "Email",
                        ProviderKey = info?.ProviderKey ?? email
                    }), user);
                    
                    await _signInManager.SignInAsync(user, isPersistent: model.RememberMe);
                    return RedirectToLocal(model.ReturnUrl); // Success
                }
                else
                {
                    _notice.AddErrors(ModelState, addLoginResult);
                }
            }
            else
            {
                _notice.AddErrors(ModelState, createResult);
            }


            await _userManager.DeleteAsync(userEmpty); // TODO: make atomic
            return View(nameof(Register), model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Lockout()
        {
            return View();
        }
  
        #region Helpers

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Notice), "Home", new NoticeViewModel
                {
                    NoticeType = NoticeType.Success,
                    Title = " ",
                    Description = " ",
                    ShowBackButton = false
                });
            }
        }

        private int MaxLoginsAllowed { get
            {
                return Int32.Parse(_configuration["Cierge:Logins:MaxLoginsAllowed"] ?? "5");
            } }

        private bool DidReachMaxLoginsAllowed(ApplicationUser user)
        {
            // Check to see if user reached max logins

            var userLoginCount = _context.UserLogins.Count(l => l.UserId == user.Id);
            return userLoginCount >= MaxLoginsAllowed;
        }

        private string GenerateUserName(string name)
        {
            name = name.Split("@")[0] ?? "";
            Regex rgx = new Regex("[^a-zA-Z0-9_-]");
            return rgx.Replace(name, "").ToLower();
        }

        #endregion
    }
}
