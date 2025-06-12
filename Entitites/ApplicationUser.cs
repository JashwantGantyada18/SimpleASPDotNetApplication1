using Microsoft.AspNetCore.Identity;

namespace AuthService.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public string Name { get; set; }
    }
}
