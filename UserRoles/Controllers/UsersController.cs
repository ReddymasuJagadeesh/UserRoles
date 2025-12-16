using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using UserRoles.Models;

namespace UserRoles.Controllers
{
    [Authorize(Roles = "Admin,Manager")]
    public class UsersController : Controller
    {
        private readonly UserManager<Users> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UsersController(
            UserManager<Users> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        /* ===================== USERS LIST ===================== */
        public async Task<IActionResult> Index()
        {
            var currentUserId = _userManager.GetUserId(User);
            bool isManager = User.IsInRole("Manager");

            var allUsers = _userManager.Users.ToList();
            var visibleUsers = new List<Users>();

            foreach (var user in allUsers)
            {
                // Hide self
                if (user.Id == currentUserId)
                    continue;

                if (isManager)
                {
                    if (await _userManager.IsInRoleAsync(user, "Admin")) continue;
                    if (await _userManager.IsInRoleAsync(user, "Manager")) continue;
                }

                visibleUsers.Add(user);
            }

            return View(visibleUsers);
        }

        /* ===================== CREATE USER ===================== */
        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(
            string firstName,
            string email,
            string password,
            string role)
        {
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
            {
                ModelState.AddModelError("", "Email and Password are required.");
                return View();
            }

            // Prevent duplicate email
            if (await _userManager.FindByEmailAsync(email) != null)
            {
                ModelState.AddModelError("", "Email already exists.");
                return View();
            }

            var user = new Users
            {
                FirstName = firstName,
                Email = email,
                UserName = email
            };

            var result = await _userManager.CreateAsync(user, password);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError("", error.Description);

                return View();
            }

            // Ensure role exists
            if (!await _roleManager.RoleExistsAsync(role))
            {
                await _roleManager.CreateAsync(new IdentityRole(role));
            }

            await _userManager.AddToRoleAsync(user, role);

            TempData["Success"] = "User created successfully.";
            return RedirectToAction(nameof(Index));
        }

        /* ===================== EDIT USER ===================== */
        public async Task<IActionResult> Edit(string id)
        {
            if (string.IsNullOrEmpty(id))
                return BadRequest();

            var user = await _userManager.FindByIdAsync(id);
            return user == null ? NotFound() : View(user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(
            string id,
            string firstName,
            string email,
            string password)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            // Email uniqueness check
            var existing = await _userManager.FindByEmailAsync(email);
            if (existing != null && existing.Id != user.Id)
            {
                ModelState.AddModelError("", "Email already in use.");
                return View(user);
            }

            user.FirstName = firstName;
            user.Email = email;
            user.UserName = email;

            await _userManager.UpdateAsync(user);

            // Optional password reset
            if (!string.IsNullOrWhiteSpace(password))
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var pwdResult = await _userManager.ResetPasswordAsync(user, token, password);

                if (!pwdResult.Succeeded)
                {
                    foreach (var err in pwdResult.Errors)
                        ModelState.AddModelError("", err.Description);

                    return View(user);
                }
            }

            TempData["Success"] = "User updated successfully.";
            return RedirectToAction(nameof(Index));
        }

        /* ===================== DELETE USER ===================== */
        public async Task<IActionResult> Delete(string id)
        {
            if (string.IsNullOrEmpty(id))
                return BadRequest();

            var user = await _userManager.FindByIdAsync(id);
            return user == null ? NotFound() : View(user);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            await _userManager.DeleteAsync(user);

            TempData["Success"] = "User deleted successfully.";
            return RedirectToAction(nameof(Index));
        }
    }
}
