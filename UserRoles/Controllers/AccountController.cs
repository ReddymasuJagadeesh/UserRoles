using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using UserRoles.Models;
using UserRoles.Services;
using UserRoles.ViewModels;

namespace UserRoles.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<Users> signInManager;
        private readonly UserManager<Users> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IEmailService emailService;

        public AccountController(SignInManager<Users> signInManager,
                                 UserManager<Users> userManager,
                                 RoleManager<IdentityRole> roleManager,
                                 IEmailService emailService)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.emailService = emailService;
        }

        // ------------------- LOGIN -------------------

        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // 🔥 FORCE NON-PERSISTENT COOKIE (session cookie)
            var result = await signInManager.PasswordSignInAsync(
                model.Email, model.Password, isPersistent: false, lockoutOnFailure: false);

            if (result.Succeeded)
            {
                // Return where user came from if protected resource redirected them
                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                    return Redirect(returnUrl);

                // ROLE-BASED REDIRECT
                var user = await userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    var roles = await userManager.GetRolesAsync(user);

                    if (roles.Contains("Admin"))
                        return RedirectToAction("Admin", "Home");

                    if (roles.Contains("Manager"))
                        return RedirectToAction("Manager", "Home");

                    if (roles.Contains("User"))
                        return RedirectToAction("Index", "Reports");
                }

                // FALLBACK
                return RedirectToAction("Index", "Home");
            }

            ModelState.AddModelError("", "Invalid Login Attempt.");
            return View(model);
        }

        // ------------------- REGISTER -------------------

        [HttpGet]
        public IActionResult Register() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = new Users
            {
                FirstName = model.Name,
                UserName = model.Email,
                NormalizedUserName = model.Email.ToUpper(),
                Email = model.Email,
                NormalizedEmail = model.Email.ToUpper()
            };

            var createResult = await userManager.CreateAsync(user, model.Password);

            if (createResult.Succeeded)
            {
                // Ensure User role exists
                if (!await roleManager.RoleExistsAsync("User"))
                    await roleManager.CreateAsync(new IdentityRole("User"));

                await userManager.AddToRoleAsync(user, "User");

                // After register → redirect to login
                return RedirectToAction("Login", "Account");
            }

            foreach (var error in createResult.Errors)
                ModelState.AddModelError("", error.Description);

            return View(model);
        }

        // ------------------- PASSWORD RESET -------------------

        [HttpGet]
        public IActionResult VerifyEmail() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyEmail(VerifyEmailViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "User not found!");
                return View(model);
            }

            var token = await userManager.GenerateEmailConfirmationTokenAsync(user);

            var link = Url.Action(
                "ChangePassword", "Account",
                new { email = model.Email, token = token },
                Request.Scheme);

            await emailService.SendEmailAsync(model.Email, "Reset Password", $"Click the link: {link}");

            return RedirectToAction("EmailSent");
        }

        [HttpGet]
        public IActionResult ChangePassword(string email, string token)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token))
                return RedirectToAction("VerifyEmail");

            return View(new ChangePasswordViewModel { Email = email, token = token });
        }

        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Something went wrong");
                return View(model);
            }

            var user = await userManager.FindByEmailAsync(model.Email);

            if (user == null)
            {
                ModelState.AddModelError("", "User not found!");
                return View(model);
            }

            var resetResult = await userManager.ResetPasswordAsync(user, model.token, model.NewPassword);

            if (!resetResult.Succeeded)
            {
                foreach (var error in resetResult.Errors)
                    ModelState.AddModelError("", error.Description);
            }
            else
            {
                return RedirectToAction("Login");
            }

            return View(model);
        }

        // ------------------- MISC -------------------

        [HttpGet]
        public IActionResult EmailSent() => View();

        [HttpGet]
        public IActionResult AccessDenied(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
    }
}
