using FluentAssertions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using System.Net;
using System.Net.Http.Json;

namespace midas.tests
{
    public class HttpTests
    {
        private ApiFactory _factory = null!;
        private HttpClient _client = null!;

        [SetUp]
        public void Setup()
        {
            _factory = new ApiFactory();
            _client = _factory.CreateClient();
        }

        [Test]
        public async Task Otp_Get_Should_Return_200_When_User_Is_Member()
        {
            // Arrange
            _factory.MembershipMock
                .IsMember("123", "0501234567")
                .Returns(true);

            _factory.OtpMock.Generate().Returns("1111");
            _factory.OtpMock.Save("123", "0501234567", "1111").Returns(true);

            // Act
            var response = await _client.GetAsync("/api/otp?id=123&phoneNum=0501234567");

            // Assert
            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Test]
        public async Task Otp_Get_Should_Return_Error_When_Not_Member()
        {
            _factory.MembershipMock
                .IsMember("123", "0000000")
                .Returns(false);

            var response = await _client.GetAsync("/api/otp?id=123&phoneNum=0000000");

            var body = await response.Content.ReadAsStringAsync();

            body.Should().Contain("no_customer");
        }

        [Test]
        public async Task Otp_Get_Should_Save_And_Send_SMS()
        {
            _factory.MembershipMock.IsMember("1", "050").Returns(true);

            _factory.OtpMock.Generate().Returns("7777");
            _factory.OtpMock.Save("1", "050", "7777").Returns(true);

            var resp = await _client.GetAsync("/api/otp?id=1&phoneNum=050");

            await _factory.SmsMock.Received(1).Send("050", "7777");
        }

        [Test]
        public async Task Otp_Get_Should_Return_Error_Response_On_ApplicationException()
        {
            _factory.MembershipMock.IsMember(Arg.Any<string>(), Arg.Any<string>())
                .Throws(new ApplicationException("Test error"));

            var resp = await _client.GetAsync("/api/otp?id=1&phoneNum=050");

            var text = await resp.Content.ReadAsStringAsync();

            text.Should().Contain("Test error");
            text.Should().Contain("\"IsError\":true");
            text.Should().Contain("\"ErrorId\":12");
        }

        [Test]
        public async Task Token_Post_Should_Return_Tokens_When_Otp_Is_Valid()
        {
            _factory.OtpMock.RetrieveOID("1234").Returns("OID-999");

            _factory.JwtMock.IssueForSubject("OID-999")
                .Returns(callInfo => Task.FromResult(new Models.AuthTokens { AccessToken = "AAA", RefreshToken = "BBB" }));

            var request = new
            {
                code = "1234"
            };

            var response = await _client.PostAsJsonAsync("/api/token", request);

            var body = await response.Content.ReadAsStringAsync();

            body.Should().Contain("access_token");
            body.Should().Contain("AAA");
        }

        [Test]
        public async Task Token_Post_Should_Return_Unknown_OTP_When_Not_Found()
        {
            _factory.OtpMock.RetrieveOID("1234").Returns((string?)null);

            var response = await _client.PostAsJsonAsync("/api/token", new { code = "1234" });

            var body = await response.Content.ReadAsStringAsync();

            body.Should().Contain("Unknown OTP");
        }

        [Test]
        public async Task Token_Post_Should_Return_Error_Response_On_Exception()
        {
            _factory.OtpMock.RetrieveOID(Arg.Any<string>())
                .Throws(new Exception("DB crash"));

            var response = await _client.PostAsJsonAsync("/api/token", new { code = "9999" });

            var text = await response.Content.ReadAsStringAsync();

            text.Should().Contain("DB crash");
            text.Should().Contain("\"IsError\":true");
            text.Should().Contain("\"ErrorId\":11");
        }
    }
}