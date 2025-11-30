namespace midas.Services.JWT
{
    public class OidcOptions
    {
        public required string ClientID { get; set; }
        public required string TenantID { get; set; }
        public required string ClientSecret { get; set; }
    }
}
