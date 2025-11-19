using System.Text.Json.Serialization;

namespace midas.Models.SMS
{
    [Serializable]
    public class SMSPayload
    {
        [JsonPropertyName("applicationId")]
        public string? applicationId { get; set; }

        [JsonPropertyName("transactionId")]
        public string? transactionId { get; set; }

        [JsonPropertyName("deliveryName")]
        public string? deliveryName { get; set; }

        [JsonPropertyName("messages")]
        public List<SMSMessage> messages { get; set; }
    }
}
