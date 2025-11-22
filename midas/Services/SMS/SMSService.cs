using Microsoft.Extensions.Options;
using midas.Models.SMS;
using System.Resources;

namespace midas.Services.SMS
{
    public class SMSService(IOptions<SMSSendOptions> options,
                            HttpClient http,
                            ILogger<ISMSService> logger) : ISMSService
    {
        private readonly SMSSendOptions sendOptions = options.Value;
        private readonly HttpClient _client = http;
        private readonly ILogger<ISMSService> _logger = logger;

        public async Task Send(string To, string Otp)
        {
            _logger.LogInformation($"{_client.BaseAddress}");

            HttpClient client = new();
            client.DefaultRequestHeaders.Add("Ocp-Apim-Subscription-Key", sendOptions.SubscriptionKey);

            var smsServiceURL = sendOptions.EndpointUrl;
            var smsSubscriptionKey = sendOptions.SubscriptionKey;
            var smsAppId = options.Value.AppId;

            var smsMessage = Resources.sms_message;

            string message = $"{smsMessage}\n{Otp}";
            var recipients = new List<string>
                {
                    To
                };

            var messages = new List<SMSMessage>
                {
                    new()
                    {
                        transactinId = Guid.NewGuid().ToString(),
                        message = message,
                        recipient = recipients
                    }
                };

            SMSPayload smsContent = new()
            {
                ApplicationId = smsAppId,
                Messages = messages
            };

            var content = new StringContent(System.Text.Json.JsonSerializer.Serialize(smsContent), null, "application/json");
            HttpResponseMessage httpResponseMessage = await client.PostAsync(smsServiceURL, content);

            httpResponseMessage.EnsureSuccessStatusCode();

            string body = await httpResponseMessage.Content.ReadAsStringAsync();
            _logger.LogInformation("SMS Service Response: {responseBody}", body);

        }
    }
}
