using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace midas.Models.SMS
{
    [Serializable]
    public class SMSMessage
    {
        [JsonPropertyName("transactinId")]
        public required string transactinId { get; set; }

        [JsonPropertyName("message")]
        public required string message { get; set; }

        [JsonPropertyName("recipient")]
        public required List<string> recipient { get; set; }
    }
}
