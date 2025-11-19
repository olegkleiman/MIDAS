namespace midas.Services.Membership
{
    public class MembershipService : IMembershipService
    {
        public Task<bool> IsMember(string userID)
        {
            // TODO: Implement actual membership check logic
            return Task.FromResult(true);
        }
    }
}
