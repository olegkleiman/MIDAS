using Microsoft.EntityFrameworkCore;

namespace midas.Services.Db
{
    public class HRDbContext : DbContext
    {
        public HRDbContext(DbContextOptions<HRDbContext> options)
            : base(options)
        {
        }

        protected HRDbContext(DbContextOptions contextOptions)
            : base(contextOptions)
        {
        }

        [DbFunction("fn_check_ID_phone", "dbo")]
        public bool IsMember(string userId, string phoneNumber)
        {
            throw new NotImplementedException();
        }

    }
}
