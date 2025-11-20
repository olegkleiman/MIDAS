using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Options;
using midas.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.KeyVaultExtensions;

namespace midas.Services.JWT
{
    public class JWTIssuerService(IOptions<JWTIssuerOptions> jwtOptions,
                                  IOptions<OidcOptions> oidcOptions) : IJWTIssuerService
    {
        private readonly JWTIssuerOptions issuerOptions = jwtOptions.Value;
        private readonly OidcOptions oidcOptions = oidcOptions.Value;

        public async Task<AuthTokens> IssueForSubject(string subject)
        {
            var clientId = oidcOptions.ClientID;
            var tenantId = oidcOptions.TenantID;
            var clientSecret = oidcOptions.ClientSecret;

            var credentials = new ClientSecretCredential(
                tenantId,
                clientId,
                clientSecret
            );

            var keyClient = new KeyClient(new Uri(issuerOptions.KeyVaultUrl), credentials);
            KeyVaultKey key = await keyClient.GetKeyAsync(issuerOptions.KeyName);

            var securityKey = new KeyVaultRsaSecurityKey(key.Id.ToString());

            var signingCredentials = new SigningCredentials(securityKey,
                                                            SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory
                {
                    CustomCryptoProvider = new KeyVaultCryptoProvider()
                }
            };

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, subject)
            };

            var token = new JwtSecurityToken(
                issuer: issuerOptions.Issuer,
                audience: issuerOptions.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(issuerOptions.ExpiredInHours),
                signingCredentials: signingCredentials
            );

            return new AuthTokens()
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
                RefreshToken = Guid.NewGuid().ToString() // TODO
            };
        }

    }
}
