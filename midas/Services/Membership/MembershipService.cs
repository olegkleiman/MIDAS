using Microsoft.EntityFrameworkCore;
using midas.Services.Db;
using System.Data;
using System.Data.Common;

namespace midas.Services.Membership
{
    public class MembershipService(HRDbContext dbContext) : IMembershipService
    {
        private readonly HRDbContext _dbContext = dbContext;

        public bool IsMember(string userID, string phoneNumber)
        {
            //_dbContext.IsMember(userID, phoneNumber);

            DbConnection conn = _dbContext.Database.GetDbConnection();

            conn.Open();
            using DbCommand command = conn.CreateCommand();
            command.CommandType = CommandType.Text;
            command.CommandText = string.Format(@"select [dbo].[fn_check_ID_phone]('{0}','{1}')", userID, phoneNumber);

            int? result = (int?)command.ExecuteScalar();

            return (result > 2);
        }
    }
}
