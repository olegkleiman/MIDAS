namespace midas.Services.JWT
{
    public class JWTIssuerOptions
    {
        public int ExpiredInHours { get; set; }
        public required string Issuer { get; set; }
        public required string Audience { get; set; }
        public required string KeyVaultUrl { get; set; }
    }
}
