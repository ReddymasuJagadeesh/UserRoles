using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace UserRoles.Models
{
    public class DailyReport
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [Column(TypeName = "date")]
        public DateTime Date { get; set; }

        [Required]
        [StringLength(500)]
        public string Task { get; set; } = string.Empty;

        [Required]
        [StringLength(2000)]
        public string Note { get; set; } = string.Empty;

        [Required]
        [StringLength(256)]
        public string ReportedTo { get; set; } = string.Empty;

        // 🔴 FK (MUST MATCH AspNetUsers.Id)
        [Required]
        public string ApplicationUserId { get; set; } = string.Empty;

        // Navigation (IMPORTANT)
        [ForeignKey(nameof(ApplicationUserId))]
        public Users ApplicationUser { get; set; } = null!;

        [Required]
        public DateTime CreatedAt { get; set; }
    }
}
