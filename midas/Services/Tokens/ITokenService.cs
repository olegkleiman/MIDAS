using midas.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace midas.Services.JWT
{
    public interface ITokenService
    {
        Task<AuthTokens> IssueForSubject(string subject);
        Task<AuthTokens> IssueJWEForSubject(string subject);

        Task<IEnumerable<Claim>> VerifyJWT(string token);
        Task<Dictionary<string, object>> ValidateJweToken(string jwe);

        Task<AuthTokens?> RefreshTokens(string refreshToken);

    }
}
