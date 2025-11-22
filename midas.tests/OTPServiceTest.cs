using Microsoft.EntityFrameworkCore;
using midas.Models.Tables;
using midas.Services.Db;
using midas.Services.OTP;
using NSubstitute;

namespace midas.tests
{
    internal class OTPServiceTest
    {
        private OTPDbContext _dbContext;
        private DbSet<UsersOtp> _mockOtpDbSet;
        private OTPService _service;

        [SetUp]
        public void Setup()
        {
            // Создаем мок DbSet<UsersOtp>
            var otpData = new List<UsersOtp>().AsQueryable();

            _mockOtpDbSet = Substitute.For<DbSet<UsersOtp>, IQueryable<UsersOtp>>();
            var queryable = (IQueryable<UsersOtp>)_mockOtpDbSet;
            queryable.Provider.Returns(otpData.Provider);
            queryable.Expression.Returns(otpData.Expression);
            queryable.ElementType.Returns(otpData.ElementType);
            queryable.GetEnumerator().Returns(otpData.GetEnumerator());

            // Мок DbContext
            _dbContext = Substitute.For<OTPDbContext>();
            _dbContext.Otps.Returns(_mockOtpDbSet);
            _dbContext.SaveChanges().Returns(1);

            _service = new OTPService(_dbContext);
        }

        [Test]
        public void Save_Adds_OTP_And_Calls_SaveChanges()
        {
            string userId = "user1";
            string phone = "0501234567";
            string otpCode = "123456";

            var result = _service.Save(userId, phone, otpCode);

            Assert.IsTrue(result);

            // Проверяем, что DbSet.Add вызван
            _mockOtpDbSet.Received().Add(Arg.Is<UsersOtp>(
                u => u.user_id == userId &&
                     u.phone_number == phone &&
                     u.plain_otp == otpCode
            ));

            // Проверяем, что SaveChanges вызван
            _dbContext.Received().SaveChanges();
        }

        [Test]
        public void RetrieveOID_Returns_Guid_String()
        {
            var code = "anycode";
            var oid = _service.RetrieveUserId(code);

            Assert.IsNotNull(oid);
            Assert.IsTrue(System.Guid.TryParse(oid, out _));
        }
    }
}


