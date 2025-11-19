using midas.Models;

namespace midas.Services.JWT
{
    public interface IJWTIssuerService
    {
        Task<AuthTokens> IssueForSubject(string subject);
    }
}
