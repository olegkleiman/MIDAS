namespace midas.Services.JWT
{
    public class TokenOptions
    {
        public int ExpiredInHours { get; set; }
        public int RefreshTokenExpiredInDays { get; set; }
        public required string Issuer { get; set; }
        public required string Audience { get; set; }
        public required string KeyVaultUrl { get; set; }
        public required string KeyName { get; set; }
        public required string RefreshTokenSecretName { get; set; }
        public required string OidSecretName { get; set; }
    }
}
