using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace midas.Models.SMS
{
    [Serializable]
    public class SMSMessage
    {
        [JsonPropertyName("transactinId")]
        public string transactinId { get; set; }

        [JsonPropertyName("message")]
        public string message { get; set; }

        [JsonPropertyName("recipient")]
        public List<string> recipient { get; set; }
    }
}
