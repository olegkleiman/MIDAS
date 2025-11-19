namespace midas.Services.SMS
{
    public class SMSSendOptions
    {
        public required string EndpointUrl { get; set; }
        public required string SubscriptionKey { get; set; }
        public required string AppId { get; set; }
    }
}
