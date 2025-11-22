using midas.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace midas.Services.JWT
{
    public interface IJWTIssuerService
    {
        Task<AuthTokens> IssueForSubject(string subject);
        public Task<IEnumerable<Claim>> VerifyToken(string token);
    }
}
