using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace UserRoles.Migrations
{
    public partial class UniqueReportPerUserPerDay : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Create unique index on ApplicationUserId + Date
            // Note: controller normalizes model.Date to UTC midnight so this index enforces a single calendar-day row per user.
            migrationBuilder.CreateIndex(
                name: "IX_DailyReports_ApplicationUserId_Date",
                table: "DailyReports",
                columns: new[] { "ApplicationUserId", "Date" },
                unique: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_DailyReports_ApplicationUserId_Date",
                table: "DailyReports");
        }
    }
}
