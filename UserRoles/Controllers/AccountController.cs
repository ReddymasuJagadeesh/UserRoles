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

        public AccountController(
            SignInManager<Users> signInManager,
            UserManager<Users> userManager,
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.emailService = emailService;
        }

        /* ===================== LOGIN ===================== */

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
            if (!ModelState.IsValid)
                return View(model);

            var result = await signInManager.PasswordSignInAsync(
                model.Email,
                model.Password,
                isPersistent: false,
                lockoutOnFailure: false);

            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Invalid login attempt.");
                return View(model);
            }

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

            return RedirectToAction("Index", "Home");
        }

        /* ===================== PASSWORD RESET ===================== */

        [HttpGet]
        public IActionResult VerifyEmail() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyEmail(VerifyEmailViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await userManager.FindByEmailAsync(model.Email);

            // 🔐 Security: do not reveal user existence
            if (user == null)
                return RedirectToAction(nameof(EmailSent));

            var today = DateTime.UtcNow.Date;

            // 🔁 Reset counter if date changed
            if (user.PasswordResetDate == null || user.PasswordResetDate.Value.Date != today)
            {
                user.PasswordResetDate = today;
                user.PasswordResetCount = 0;
            }

            // 🚫 LIMIT CHECK
            if (user.PasswordResetCount >= 3)
            {
                ModelState.AddModelError("", "You have reached the maximum of 3 password reset attempts for today.");
                return View(model);
            }

            // ✅ Generate reset token
            var token = await userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = Uri.EscapeDataString(token);

            var resetLink = Url.Action(
                "ChangePassword",
                "Account",
                new { email = user.Email, token = encodedToken },
                Request.Scheme
            );

            await emailService.SendEmailAsync(
                user.Email,
                "Reset your password",
                $"Click the link below to reset your password:\n\n{resetLink}"
            );

            // 🔢 Increment usage
            user.PasswordResetCount += 1;
            await userManager.UpdateAsync(user);

            // 📊 Show remaining attempts
            TempData["RemainingAttempts"] = 3 - user.PasswordResetCount;

            return RedirectToAction(nameof(EmailSent));
        }

        

        [HttpGet]
        public IActionResult ChangePassword(string email, string token)
        {
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(token))
                return RedirectToAction(nameof(VerifyEmail));

            return View(new ChangePasswordViewModel
            {
                Email = email,
                Token = token
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "Invalid request.");
                return View(model);
            }

            // ✅ DECODE TOKEN
            var decodedToken = Uri.UnescapeDataString(model.Token);

            var result = await userManager.ResetPasswordAsync(
                user,
                decodedToken,
                model.NewPassword);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError("", error.Description);

                return View(model);
            }

            return RedirectToAction(nameof(Login));
        }

        /* ===================== MISC ===================== */

        [HttpGet]
        public IActionResult EmailSent() => View();

        [HttpGet]
        public IActionResult AccessDenied() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
    }
}
