using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using UserRoles.Models;

namespace UserRoles.Data
{
    public class AppDbContext : IdentityDbContext<Users>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options)
            : base(options) { }

        public DbSet<DailyReport> DailyReports { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // ✅ ONE REPORT PER USER PER DAY
            builder.Entity<DailyReport>()
                .HasIndex(r => new { r.ApplicationUserId, r.Date })
                .IsUnique();

            // ✅ DATE ONLY (NO TIME)
            builder.Entity<DailyReport>()
                .Property(r => r.Date)
                .HasColumnType("date");

            // ✅ FORCE UTC
            builder.Entity<DailyReport>()
                .Property(r => r.CreatedAt)
                .HasConversion(
                    v => v,
                    v => DateTime.SpecifyKind(v, DateTimeKind.Utc)
                );
        }
    }
}
