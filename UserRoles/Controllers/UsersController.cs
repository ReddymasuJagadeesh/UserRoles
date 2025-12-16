using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using UserRoles.Helpers;
using UserRoles.Models;
using UserRoles.Services;

namespace UserRoles.Controllers
{
    [Authorize(Roles = "Admin,Manager")]
    public class UsersController : Controller
    {
        private readonly UserManager<Users> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;

        public UsersController(
            UserManager<Users> userManager,
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
        }

        /* ================= USERS LIST ================= */
        public async Task<IActionResult> Index()
        {
            var currentUserId = _userManager.GetUserId(User);
            bool isManager = User.IsInRole("Manager");

            var visibleUsers = new List<Users>();

            foreach (var user in _userManager.Users.ToList())
            {
                // Hide self
                if (user.Id == currentUserId)
                    continue;

                if (isManager)
                {
                    // Manager cannot see Admin / Manager
                    if (await _userManager.IsInRoleAsync(user, "Admin")) continue;
                    if (await _userManager.IsInRoleAsync(user, "Manager")) continue;
                }

                visibleUsers.Add(user);
            }

            return View(visibleUsers);
        }

        /* ================= CREATE USER ================= */
        public IActionResult Create() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(
    string firstName,
    string email,
    string role)
        {
            // ================= BASIC VALIDATION =================
            if (string.IsNullOrWhiteSpace(email))
            {
                ModelState.AddModelError("", "Email is required.");
                return View();
            }

            if (await _userManager.FindByEmailAsync(email) != null)
            {
                ModelState.AddModelError("", "Email already exists.");
                return View();
            }

            // ================= ROLE SECURITY RULE =================
            bool isAdmin = User.IsInRole("Admin");
            bool isManager = User.IsInRole("Manager");

            // ❌ Manager CANNOT create Manager
            if (isManager && role == "Manager")
            {
                return Forbid(); // strong security
            }

            // ❌ Non-admin cannot create Admin
            if (!isAdmin && role == "Admin")
            {
                return Forbid();
            }

            // ================= PASSWORD GENERATION =================
            string generatedPassword = PasswordHelper.GeneratePassword();

            var user = new Users
            {
                FirstName = firstName?.Trim(),
                Email = email.Trim(),
                UserName = email.Trim(),
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, generatedPassword);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError("", error.Description);

                return View();
            }

            // ================= ROLE CREATION =================
            if (!await _roleManager.RoleExistsAsync(role))
            {
                await _roleManager.CreateAsync(new IdentityRole(role));
            }

            await _userManager.AddToRoleAsync(user, role);

            // ================= EMAIL =================
            string loginUrl = Url.Action(
                "Login",
                "Account",
                null,
                Request.Scheme
            )!;

            string subject = "Your Account Credentials";
            string body = $@"
Hello {firstName},

Your account has been created.

Login Email: {email}
Temporary Password: {generatedPassword}

Please login and change your password immediately.

Login URL:
{loginUrl}

Thanks,
Admin Team";

            await _emailService.SendEmailAsync(email, subject, body);

            TempData["Success"] = "User created successfully and credentials sent.";
            return RedirectToAction(nameof(Index));
        }


        /* ================= INLINE UPDATE ================= */
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> InlineUpdate(string id, string firstName, string email)
        {
            var currentUserId = _userManager.GetUserId(User);
            var user = await _userManager.FindByIdAsync(id);

            if (user == null || user.Id == currentUserId)
                return Forbid();

            bool isManager = User.IsInRole("Manager");
            if (isManager)
            {
                if (await _userManager.IsInRoleAsync(user, "Admin")) return Forbid();
                if (await _userManager.IsInRoleAsync(user, "Manager")) return Forbid();
            }

            var existing = await _userManager.FindByEmailAsync(email);
            if (existing != null && existing.Id != user.Id)
            {
                TempData["Error"] = "Email already exists.";
                return RedirectToAction(nameof(Index));
            }

            user.FirstName = firstName?.Trim();
            user.Email = email.Trim();
            user.UserName = email.Trim();

            await _userManager.UpdateAsync(user);
            TempData["Success"] = "User updated successfully.";

            return RedirectToAction(nameof(Index));
        }

        /* ================= DELETE USER (FIXED) ================= */
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string id)
        {
            var currentUserId = _userManager.GetUserId(User);
            var currentUser = await _userManager.FindByIdAsync(currentUserId!);
            var userToDelete = await _userManager.FindByIdAsync(id);

            if (userToDelete == null)
                return NotFound();

            // Prevent self delete
            if (userToDelete.Id == currentUserId)
                return Forbid();

            bool currentIsManager = await _userManager.IsInRoleAsync(currentUser!, "Manager");
            bool targetIsAdmin = await _userManager.IsInRoleAsync(userToDelete, "Admin");
            bool targetIsManager = await _userManager.IsInRoleAsync(userToDelete, "Manager");

            // Manager restrictions
            if (currentIsManager && (targetIsAdmin || targetIsManager))
                return Forbid();

            await _userManager.DeleteAsync(userToDelete);

            TempData["Success"] = "User deleted successfully.";
            return RedirectToAction(nameof(Index));
        }
    }
}
