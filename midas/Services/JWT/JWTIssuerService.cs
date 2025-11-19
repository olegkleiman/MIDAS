using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using midas.Models;
using System.IdentityModel.Tokens.Jwt;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace midas.Services.JWT
{
    public class JWTIssuerService(IOptions<JWTIssuerOptions> options) : IJWTIssuerService
    {
        private readonly JWTIssuerOptions issuerOptions = options.Value;

        public async Task<AuthTokens> IssueForSubject(string subject)
        {
            // TODO: Get the assumetric key from Azure KeyVault

            var clientId = "aaf81556-7561-4a46-9bd6-3aa0c707da2c";
            var tenantId = "aa640f10-95f8-4f05-96f1-529dbbc11897";
            var clientSecret = "5Zs8Q~yAwnnYh1m4GyonDLkuQwAPP77o64d9Vbvb";

            var credentials = new ClientSecretCredential(
                tenantId,
                clientId,
                clientSecret
            );
            var keyClient = new KeyClient(
                new Uri(issuerOptions.KeyVaultUrl),
                credentials // new DefaultAzureCredential()
            );
            KeyVaultKey vaultKey = await keyClient.GetKeyAsync("HRKey");

            var rsa = vaultKey.Key.ToRSA(false);
            var securityKey = new RsaSecurityKey(rsa)
            {
                KeyId = vaultKey.Key.Id
            };

            var signingCredentials = new SigningCredentials(
                securityKey,
                SecurityAlgorithms.RsaSha256
            );

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
