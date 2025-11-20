namespace midas.Services.Membership
{
    public interface IMembershipService
    {
        bool IsMember(string userID, string phoneNumber);
    }
}
