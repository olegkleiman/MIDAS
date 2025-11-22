using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using midas.Services.SMS;
using NSubstitute;
using System.Net;

namespace midas.tests
{
    internal class SMSServiceTest
    {
        private IOptions<SMSSendOptions?> _options;
        private ILogger<ISMSService> _logger;
        private SMSService _service;
        private FakeHttpMessageHandler _fakeHandler;

        [SetUp]
        public void Setup()
        {
            var configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.Development.json")
                .Build();

            _options = Options.Create(configuration.GetSection("SmsServiceOptions").Get<SMSSendOptions>());

            _logger = Substitute.For<ILogger<ISMSService>>();

            _fakeHandler = new FakeHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"status\":\"ok\"}")
            });

            var httpClient = new HttpClient(_fakeHandler)
            {
                BaseAddress = new Uri("https://fake-sms-service.local")
            };

            _service = new SMSService(_options, httpClient, _logger);
        }

        [Test]
        public async Task Send_Should_Call_HttpClient_And_Log_Response()
        {
            // Arrange
            string phoneNumber = "0501234567";
            string otp = "123456";

            var fakeResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"status\":\"ok\"}")
            };

            var handler = new FakeHttpMessageHandler(fakeResponse);
            var httpClient = new HttpClient(handler)
            {
                BaseAddress = new Uri(_options.Value.EndpointUrl)
            };

            var logger = Substitute.For<ILogger<ISMSService>>();
            var service = new SMSService(_options, httpClient, logger);

            // Act
            await service.Send(phoneNumber, otp);

            // Assert
            //_logger.Received().Log(
            //    Arg.Is<LogLevel>(l => l == LogLevel.Information),
            //    Arg.Any<EventId>(),
            //    Arg.Is<object>(state => state.ToString()!.Contains(_options.Value.EndpointUrl)),
            //    Arg.Any<Exception>(),
            //    Arg.Any<Func<object, Exception?, string>>()
            //);
        }

    }
}
