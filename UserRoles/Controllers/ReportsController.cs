using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using UserRoles.Data;
using UserRoles.Models;
using UserRoles.ViewModels;

namespace UserRoles.Controllers
{
    [Authorize]
    public class ReportsController : Controller
    {
        private readonly AppDbContext _context;
        private readonly UserManager<Users> _userManager;

        public ReportsController(AppDbContext context, UserManager<Users> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        /* ================= ENTRY ================= */
        public IActionResult Index()
        {
            var userId = _userManager.GetUserId(User);
            return RedirectToAction(nameof(UserReports), new { userId });
        }

        /* ================= USER REPORTS ================= */
        [Authorize(Roles = "User,Manager,Admin")]
        public async Task<IActionResult> UserReports(string userId)
        {
            var currentUserId = _userManager.GetUserId(User);

            // ❌ Normal user cannot view other users' reports
            if (User.IsInRole("User") && userId != currentUserId)
                return Forbid();

            var today = DateTime.Today;

            var reports = await _context.DailyReports
                .Where(r => r.ApplicationUserId == userId)
                .OrderByDescending(r => r.Date)
                .ThenByDescending(r => r.CreatedAt)
                .ToListAsync();

            ViewBag.Today = today;
            ViewBag.HasToday = reports.Any(r => r.Date.Date == today);

            // ✅ Report owner name for header display
            var owner = await _userManager.FindByIdAsync(userId);
            ViewBag.ReportOwnerName =
                owner?.FirstName ?? owner?.UserName ?? "User";

            return View(reports);
        }

        /* ================= CREATE TODAY (USER + MANAGER) ================= */
        [Authorize(Roles = "User,Manager")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateToday(
            string task,
            string note,
            List<string> reportedTo)
        {
            var userId = _userManager.GetUserId(User)!;
            var today = DateTime.Today;

            bool exists = await _context.DailyReports.AnyAsync(r =>
                r.ApplicationUserId == userId &&
                r.Date.Date == today);

            if (exists)
            {
                TempData["Error"] = "Today's report already submitted.";
                return RedirectToAction(nameof(UserReports), new { userId });
            }

            if (string.IsNullOrWhiteSpace(task) || string.IsNullOrWhiteSpace(note))
            {
                TempData["Error"] = "Task and Note are required.";
                return RedirectToAction(nameof(UserReports), new { userId });
            }

            if (reportedTo == null || !reportedTo.Any())
            {
                TempData["Error"] = "Please select Admin or Manager.";
                return RedirectToAction(nameof(UserReports), new { userId });
            }

            var report = new DailyReport
            {
                ApplicationUserId = userId,
                Date = today,
                Task = task.Trim(),
                Note = note.Trim(),
                ReportedTo = string.Join(", ", reportedTo),
                CreatedAt = DateTime.UtcNow
            };

            _context.DailyReports.Add(report);
            await _context.SaveChangesAsync();

            TempData["Success"] = "Report submitted successfully.";
            return RedirectToAction(nameof(UserReports), new { userId });
        }

        /* ================= DETAILS ================= */
        [Authorize(Roles = "User,Manager,Admin")]
        public async Task<IActionResult> Details(int id)
        {
            var report = await _context.DailyReports
                .AsNoTracking()
                .FirstOrDefaultAsync(r => r.Id == id);

            if (report == null)
                return NotFound();

            var currentUserId = _userManager.GetUserId(User);

            // ❌ User cannot view others' reports
            if (User.IsInRole("User") && report.ApplicationUserId != currentUserId)
                return Forbid();

            var owner = await _userManager.FindByIdAsync(report.ApplicationUserId);

            var vm = new ReportViewModel
            {
                Id = report.Id,
                ApplicationUserId = report.ApplicationUserId,
                UserName = owner?.UserName,
                FirstName = owner?.FirstName,
                Date = report.Date,
                Task = report.Task,
                Note = report.Note,
                ReportedTo = report.ReportedTo,
                ReviewerComment = report.ReviewerComment,
                CreatedAt = report.CreatedAt
            };

            return View(vm);
        }

        /* ================= INLINE UPDATE (ADMIN / MANAGER) ================= */
        [Authorize(Roles = "Admin,Manager")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> InlineUpdate(
            int id,
            string task,
            string note,
            string reviewerComment)
        {
            var report = await _context.DailyReports.FindAsync(id);
            if (report == null)
                return NotFound();

            var currentUserId = _userManager.GetUserId(User);

            // ❌ Admin/Manager cannot edit own report
            if (report.ApplicationUserId == currentUserId)
                return Forbid();

            report.Task = task?.Trim();
            report.Note = note?.Trim();
            report.ReviewerComment = reviewerComment?.Trim();

            await _context.SaveChangesAsync();

            TempData["Success"] = "Report updated successfully.";
            return RedirectToAction(nameof(UserReports),
                new { userId = report.ApplicationUserId });
        }

        /* ================= DELETE ================= */
        [Authorize(Roles = "Admin,Manager")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(int id)
        {
            var report = await _context.DailyReports.FindAsync(id);
            if (report == null)
                return NotFound();

            var currentUserId = _userManager.GetUserId(User);

            // ❌ Admin/Manager cannot delete own report
            if (report.ApplicationUserId == currentUserId)
                return Forbid();

            var userId = report.ApplicationUserId;

            _context.DailyReports.Remove(report);
            await _context.SaveChangesAsync();

            TempData["Success"] = "Report deleted successfully.";
            return RedirectToAction(nameof(UserReports), new { userId });
        }
    }
}
