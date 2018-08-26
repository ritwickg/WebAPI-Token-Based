using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using TokenAuthenticationNetCore.Data.Models;
using TokenAuthenticationNetCore.Models;

namespace TokenAuthenticationNetCore.Data
{
    public class ApplicationIdentityDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationIdentityDbContext(DbContextOptions<ApplicationIdentityDbContext> options) : base(options)
        {
        }
        public DbSet<VerificationEmailModel> Registrations { get; set; }
    }
}
