using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace UserRoles.Migrations
{
    /// <inheritdoc />
    public partial class savetodayreports : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<DateTime>(
                name: "Date",
                table: "DailyReports",
                type: "date",
                nullable: false,
                oldClrType: typeof(DateTime),
                oldType: "timestamp with time zone");

            migrationBuilder.CreateIndex(
                name: "IX_DailyReports_ApplicationUserId_Date",
                table: "DailyReports",
                columns: new[] { "ApplicationUserId", "Date" },
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_DailyReports_AspNetUsers_ApplicationUserId",
                table: "DailyReports",
                column: "ApplicationUserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_DailyReports_AspNetUsers_ApplicationUserId",
                table: "DailyReports");

            migrationBuilder.DropIndex(
                name: "IX_DailyReports_ApplicationUserId_Date",
                table: "DailyReports");

            migrationBuilder.AlterColumn<DateTime>(
                name: "Date",
                table: "DailyReports",
                type: "timestamp with time zone",
                nullable: false,
                oldClrType: typeof(DateTime),
                oldType: "date");
        }
    }
}
