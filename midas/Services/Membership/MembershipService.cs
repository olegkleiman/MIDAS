namespace midas.Services.Membership
{
    public class MembershipService : IMembershipService
    {
        public Task<bool> IsMember(string userID)
        {
            return Task.FromResult(true);
        }
    }
}
