using Microsoft.AspNetCore.Identity;
namespace UserRoles.Models
{
    public class Users : IdentityUser
    {
        public string? FirstName { get; set; }

        public int PasswordResetCount { get; set; } = 0;
        public DateTime? PasswordResetDate { get; set; }

    }
}
