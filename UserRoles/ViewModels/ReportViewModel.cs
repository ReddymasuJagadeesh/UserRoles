using System;

namespace UserRoles.ViewModels
{
    public class ReportViewModel
    {
        public int Id { get; set; }

        public string ApplicationUserId { get; set; }

        public string? UserName { get; set; }

        public string? FirstName { get; set; }

        public DateTime Date { get; set; }

        public string Task { get; set; }

        public string Note { get; set; }

        public string ReportedTo { get; set; }

        // ✅ THIS WAS MISSING → CAUSED ALL ERRORS
        public string? ReviewerComment { get; set; }

        public DateTime CreatedAt { get; set; }
    }
}
