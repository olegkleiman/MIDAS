namespace midas.Services.SMS
{
    public interface ISMSService
    {
        Task Send(string To, string Otp);
    }
}
