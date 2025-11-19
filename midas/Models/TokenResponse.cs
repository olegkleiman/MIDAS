using Newtonsoft.Json;

namespace midas.Models
{
    public class TokensResponse : AuthTokens
    {
        [JsonProperty("token_type")]
        public string TokenType = "bearer";

        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }

        public TokensResponse(AuthTokens tokens)
        {
            AccessToken = tokens.AccessToken;
            RefreshToken = tokens.RefreshToken;
        }
    }
}
