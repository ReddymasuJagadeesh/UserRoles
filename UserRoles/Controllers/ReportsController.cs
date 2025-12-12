using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using UserRoles.Data;
using UserRoles.Models;
using UserRoles.ViewModels;

namespace UserRoles.Controllers
{
    [Authorize(Roles = "User,Manager,Admin")]
    public class ReportsController : Controller
    {
        private readonly AppDbContext _db;
        private readonly UserManager<Users> _userManager;

        public ReportsController(AppDbContext db, UserManager<Users> userManager)
        {
            _db = db;
            _userManager = userManager;
        }

        // GET: /Reports
        public async Task<IActionResult> Index()
        {
            var currentUser = await _userManager.GetUserAsync(User);
            var isManagerOrAdmin = User.IsInRole("Manager") || User.IsInRole("Admin");

            List<DailyReport> reports;
            if (isManagerOrAdmin)
            {
                reports = await _db.DailyReports.OrderByDescending(r => r.Date).ToListAsync();
            }
            else
            {
                if (currentUser == null) return Challenge();
                reports = await _db.DailyReports
                                   .Where(r => r.ApplicationUserId == currentUser.Id)
                                   .OrderByDescending(r => r.Date)
                                   .ToListAsync();
            }

            // Build viewmodels with owner info
            var userIds = reports.Select(r => r.ApplicationUserId).Distinct().ToList();
            var users = await _userManager.Users.Where(u => userIds.Contains(u.Id)).ToListAsync();

            var vm = reports.Select(r =>
            {
                var owner = users.FirstOrDefault(u => u.Id == r.ApplicationUserId);
                return new ReportViewModel
                {
                    Id = r.Id,
                    ApplicationUserId = r.ApplicationUserId,
                    UserName = owner?.Email ?? owner?.UserName ?? "Unknown",
                    FirstName = owner?.FirstName,
                    Date = r.Date,
                    Task = r.Task,
                    Note = r.Note,
                    ReportedTo = r.ReportedTo,
                    CreatedAt = r.CreatedAt
                };
            }).ToList();

            return View(vm);
        }

        // GET: /Reports/Details/5
        public async Task<IActionResult> Details(int id)
        {
            var report = await _db.DailyReports.FindAsync(id);
            if (report == null) return NotFound();

            var currentUser = await _userManager.GetUserAsync(User);
            if (!User.IsInRole("Manager") && !User.IsInRole("Admin") && report.ApplicationUserId != currentUser?.Id)
                return Forbid();

            var owner = await _userManager.FindByIdAsync(report.ApplicationUserId);
            var vm = new ReportViewModel
            {
                Id = report.Id,
                ApplicationUserId = report.ApplicationUserId,
                UserName = owner?.Email ?? owner?.UserName,
                FirstName = owner?.FirstName,
                Date = report.Date,
                Task = report.Task,
                Note = report.Note,
                ReportedTo = report.ReportedTo,
                CreatedAt = report.CreatedAt
            };

            return View(vm);
        }

        // GET: /Reports/Create
        [Authorize(Roles = "User")]
        public IActionResult Create()
        {
            return View(new DailyReport { Date = DateTime.UtcNow.Date });
        }

        // POST: /Reports/Create
        [Authorize(Roles = "User")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(DailyReport model)
        {
            // Get logged-in user
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                TempData["CreateErrors"] = "User not found. Please login again.";
                return RedirectToAction("Login", "Account");
            }

            // Force server-side ApplicationUserId and CreatedAt
            model.ApplicationUserId = user.Id;
            model.CreatedAt = DateTime.UtcNow;

            // Convert Date to UTC because Npgsql expects UTC for timestamptz
            // Bound Date from <input type="date"> will be Kind=Unspecified; set to Utc
            model.Date = DateTime.SpecifyKind(model.Date, DateTimeKind.Utc);

            // Remove any posted ApplicationUserId from ModelState so it doesn't block validation
            if (ModelState.ContainsKey(nameof(model.ApplicationUserId)))
                ModelState.Remove(nameof(model.ApplicationUserId));

            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList();
                if (errors.Any())
                    TempData["CreateErrors"] = string.Join(" | ", errors);
                return View(model);
            }

            try
            {
                _db.DailyReports.Add(model);
                await _db.SaveChangesAsync();
            }
            catch (DbUpdateException dbEx)
            {
                var inner = dbEx.InnerException?.Message ?? dbEx.Message;
                TempData["CreateErrors"] = "Database error: " + inner;
                return View(model);
            }
            catch (Exception ex)
            {
                TempData["CreateErrors"] = "Error: " + ex.Message;
                return View(model);
            }

            TempData["CreateSuccess"] = "Report saved successfully.";
            return RedirectToAction(nameof(Index));
        }

        // GET: /Reports/Edit/5
        [Authorize]
        public async Task<IActionResult> Edit(int id)
        {
            var report = await _db.DailyReports.FindAsync(id);
            if (report == null) return NotFound();

            var user = await _userManager.GetUserAsync(User);
            bool isOwner = report.ApplicationUserId == user?.Id;
            bool isAdmin = User.IsInRole("Admin");

            if (!isOwner && !isAdmin) return Forbid();

            // When editing, convert stored UTC Date to local date for UI (optional)
            // but leave model.Date as-is; the Edit view will show the date input.
            return View(report);
        }

        // POST: /Reports/Edit/5
        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, DailyReport model)
        {
            if (id != model.Id) return BadRequest();

            // fetch the existing entity
            var report = await _db.DailyReports.FindAsync(id);
            if (report == null) return NotFound();

            var user = await _userManager.GetUserAsync(User);
            bool isOwner = report.ApplicationUserId == user?.Id;
            bool isAdmin = User.IsInRole("Admin");

            if (!isOwner && !isAdmin) return Forbid();

            // Remove any posted ApplicationUserId from ModelState
            if (ModelState.ContainsKey(nameof(model.ApplicationUserId)))
                ModelState.Remove(nameof(model.ApplicationUserId));

            // Convert incoming date to Utc
            model.Date = DateTime.SpecifyKind(model.Date, DateTimeKind.Utc);

            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList();
                if (errors.Any())
                    TempData["EditErrors"] = string.Join(" | ", errors);
                return View(model);
            }

            // Update allowed fields
            report.Date = model.Date;
            report.Task = model.Task;
            report.Note = model.Note;
            report.ReportedTo = model.ReportedTo;
            // keep ApplicationUserId and CreatedAt unchanged

            try
            {
                _db.DailyReports.Update(report);
                await _db.SaveChangesAsync();
            }
            catch (DbUpdateException dbEx)
            {
                var inner = dbEx.InnerException?.Message ?? dbEx.Message;
                TempData["EditErrors"] = "Database error: " + inner;
                return View(model);
            }
            catch (Exception ex)
            {
                TempData["EditErrors"] = "Error: " + ex.Message;
                return View(model);
            }

            TempData["EditSuccess"] = "Report updated successfully.";
            return RedirectToAction(nameof(Index));
        }

        // GET: /Reports/Delete/5
        [Authorize]
        public async Task<IActionResult> Delete(int id)
        {
            var report = await _db.DailyReports.FindAsync(id);
            if (report == null) return NotFound();

            var user = await _userManager.GetUserAsync(User);
            bool isOwner = report.ApplicationUserId == user?.Id;
            bool isManagerOrAdmin = User.IsInRole("Manager") || User.IsInRole("Admin");

            if (!isOwner && !isManagerOrAdmin) return Forbid();

            var owner = await _userManager.FindByIdAsync(report.ApplicationUserId);
            var vm = new ReportViewModel
            {
                Id = report.Id,
                ApplicationUserId = report.ApplicationUserId,
                UserName = owner?.Email ?? owner?.UserName,
                FirstName = owner?.FirstName,
                Date = report.Date,
                Task = report.Task,
                Note = report.Note,
                ReportedTo = report.ReportedTo,
                CreatedAt = report.CreatedAt
            };

            return View(vm);
        }

        // POST: /Reports/Delete/5
        [Authorize]
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var report = await _db.DailyReports.FindAsync(id);
            if (report == null) return NotFound();

            var user = await _userManager.GetUserAsync(User);
            bool isOwner = report.ApplicationUserId == user?.Id;
            bool isManagerOrAdmin = User.IsInRole("Manager") || User.IsInRole("Admin");

            if (!isOwner && !isManagerOrAdmin) return Forbid();

            try
            {
                _db.DailyReports.Remove(report);
                await _db.SaveChangesAsync();
            }
            catch (DbUpdateException dbEx)
            {
                var inner = dbEx.InnerException?.Message ?? dbEx.Message;
                TempData["DeleteErrors"] = "Database error: " + inner;
                return RedirectToAction(nameof(Delete), new { id });
            }
            catch (Exception ex)
            {
                TempData["DeleteErrors"] = "Error: " + ex.Message;
                return RedirectToAction(nameof(Delete), new { id });
            }

            TempData["DeleteSuccess"] = "Report deleted.";
            return RedirectToAction(nameof(Index));
        }
    }
}
