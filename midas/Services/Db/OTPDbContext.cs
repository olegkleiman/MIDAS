using Microsoft.EntityFrameworkCore;
using midas.Models.Tables;

namespace midas.Services.Db
{
    public class OTPDbContext : DbContext
    {
        public OTPDbContext(DbContextOptions<OTPDbContext> options)
            : base(options)
        {
        }

        protected OTPDbContext(DbContextOptions contextOptions)
            : base(contextOptions)
        {
        }

        //public DbSet<PlatformItem> Platforms { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<UsersOtp> Otps { get; set; }
    }
}
