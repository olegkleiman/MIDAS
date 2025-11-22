using System.Text.Json.Serialization;

namespace midas.Models.SMS
{
    [Serializable]
    public class SMSPayload
    {
        [JsonPropertyName("applicationId")]
        public string? ApplicationId { get; set; }

        [JsonPropertyName("transactionId")]
        public string? TransactionId { get; set; }

        [JsonPropertyName("deliveryName")]
        public string? DeliveryName { get; set; }

        [JsonPropertyName("messages")]
        public List<SMSMessage>? Messages { get; set; }
    }
}
