using Newtonsoft.Json;

namespace midas.Models
{
    public class AuthTokens
    {
        [JsonProperty("access_token")]
        public string? AccessToken { get; set; }
        [JsonProperty("refresh_token")]
        public string? RefreshToken { get; set; }
    }
}
