using Microsoft.AspNetCore.Identity;

namespace TokenAuthenticationNetCore.Models
{
    /// <summary>
    /// Custom class inheriting IdentityUser to implement custom profile of user
    /// </summary>
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public int Age { get; set; }
    }
}
