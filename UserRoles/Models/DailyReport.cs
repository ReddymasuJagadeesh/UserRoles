using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace UserRoles.Models
{
    public class DailyReport
    {
        public int Id { get; set; }

        [Required]
        public string ApplicationUserId { get; set; } = null!;

        [Column(TypeName = "date")]
        public DateTime Date { get; set; }

        [Required]
        [MaxLength(300)]
        public string Task { get; set; } = null!;

        [Required]
        public string Note { get; set; } = null!;

        public string ReportedTo { get; set; } = null!;

        // ✅ Admin / Manager comment
        public string? ReviewerComment { get; set; }

        public DateTime CreatedAt { get; set; }
    }
}
