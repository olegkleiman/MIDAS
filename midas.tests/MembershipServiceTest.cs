using NUnit.Framework;
using NSubstitute;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using System.Data.Common;
using System.Data;
using midas.Services.Db;
using midas.Services.Membership;
using System.Threading.Tasks;

namespace midas.tests
{
    internal class MembershipServiceTest
    {
        private HRDbContext         _dbContext;
        private DbConnection        _mockConnection;
        private DbCommand           _mockCommand;
        private MembershipService   _service;

        [SetUp]
        public void Setup()
        {
            // Мок DbCommand
            _mockCommand = Substitute.For<DbCommand>();
            _mockCommand.CommandType = CommandType.Text;

            // Мок DbConnection
            _mockConnection = Substitute.For<DbConnection>();
            _mockConnection.CreateCommand().Returns(_mockCommand);

            // Мок DatabaseFacade для DbContext
            var dbContext = Substitute.For<HRDbContext>(new DbContextOptions<HRDbContext>());
            dbContext.Database.GetDbConnection().Returns(_mockConnection);

            _dbContext = dbContext;
            _service = new MembershipService(_dbContext);
        }

        [Test]
        public void IsMember_Returns_True_When_Result_Greater_Than_2()
        {
            // Arrange
            _mockCommand.ExecuteScalar().Returns(3); // > 2

            // Act
            var result = _service.IsMember("user1", "0501234567");

            // Assert
            Assert.IsTrue(result);
            Assert.IsTrue(_mockCommand.CommandText.Contains("user1") && _mockCommand.CommandText.Contains("0501234567"));
        }

        [Test]
        public void IsMember_Returns_False_When_Result_Less_Or_Equal_2()
        {
            _mockCommand.ExecuteScalar().Returns(2); // <= 2

            var result = _service.IsMember("user2", "0507654321");

            Assert.IsFalse(result);
        }

        [Test]
        public void IsMember_Returns_False_When_Result_Is_Null()
        {
            _mockCommand.ExecuteScalar().Returns((int?)null); // null from DB

            var result = _service.IsMember("user3", "0500000000");

            Assert.IsFalse(result);
        }
    }
}
