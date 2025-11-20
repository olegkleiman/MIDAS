using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Options;
using midas.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.KeyVaultExtensions;
using Azure.Security.KeyVault.Secrets;
using midas.Utils;

namespace midas.Services.JWT
{
    public class JWTIssuerService(IOptions<JWTIssuerOptions> jwtOptions,
                                  IOptions<OidcOptions>      oidcOptions,
                                  ILogger<JWTIssuerService>  logger) : IJWTIssuerService
    {
        private readonly JWTIssuerOptions _issuerOptions     = jwtOptions.Value;
        private readonly OidcOptions      _oidcOptions       = oidcOptions.Value;
        private readonly ILogger<JWTIssuerService> _logger   = logger;

        private readonly DateTime _epoch = new(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public ClientSecretCredential _credentials => new ClientSecretCredential(
            _oidcOptions.TenantID,
            _oidcOptions.ClientID,
            _oidcOptions.ClientSecret
        );

        private string CreateRefreshToken(string oid)
        {
            var secretClient = new SecretClient(new Uri(_issuerOptions.KeyVaultUrl), _credentials);

            try
            {
                KeyVaultSecret secret = secretClient.GetSecret(_issuerOptions.SecretName);
                EncryptionHelper encryptionHelper = new(secret.Value);
                long exp = (long)(DateTime.UtcNow.AddDays(60) - _epoch).TotalSeconds;
                return encryptionHelper.Encrypt($"{oid};{exp}");
            }
            catch(Exception ex)
            {
                _logger.LogError($"Failed to create refresh token: {ex.Message}");
            }

            return string.Empty;
        }

        public async Task<AuthTokens> IssueForSubject(string subject)
        {
            var refreshToken = CreateRefreshToken(subject);

            var keyClient = new KeyClient(new Uri(_issuerOptions.KeyVaultUrl), _credentials);
            KeyVaultKey key = await keyClient.GetKeyAsync(_issuerOptions.KeyName);

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
                issuer: _issuerOptions.Issuer,
                audience: _issuerOptions.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(_issuerOptions.ExpiredInHours),
                signingCredentials: signingCredentials
            );

            return new AuthTokens()
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
                RefreshToken = refreshToken
            };
        }

    }
}
