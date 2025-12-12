using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using UserRoles.Models;

namespace UserRoles.Models
{
    public class DailyReport
    {
        [Key]
        public int Id { get; set; }             // S.No (auto-increment)

        [Required]
        public DateTime Date { get; set; } = DateTime.UtcNow;

        [Required]
        [StringLength(500)]
        public string Task { get; set; }

        [StringLength(2000)]
        public string Note { get; set; }        // comment

        [StringLength(256)]
        public string ReportedTo { get; set; }  // manager email or name

        // FK to ApplicationUser (Identity)
        [Required]
        public string ApplicationUserId { get; set; }

       

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}

