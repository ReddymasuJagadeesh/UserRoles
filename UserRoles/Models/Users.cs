using Microsoft.AspNetCore.Identity;
namespace UserRoles.Models
{
    public class Users : IdentityUser
    {
        public string? FirstName { get; set; }
       
    }
}
