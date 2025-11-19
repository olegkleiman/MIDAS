namespace midas.Services.Membership
{
    public interface IMembershipService
    {
        Task<bool> IsMember(string userID);
    }
}
