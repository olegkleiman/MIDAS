using Azure.Core.Diagnostics;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using midas.Services.JWT;
using midas.Services.SMS;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace midas.tests
{
    internal class JwtSignVerificationTest
    {
        private OidcOptions?    _oidcOptions;
        private TokenOptions?   _jwtOptions;


        [SetUp]
        public void Setup()
        {
            var configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.Development.json")
                .Build();

            _oidcOptions = configuration.GetSection("OidcOptions").Get<OidcOptions>();
            _jwtOptions = configuration.GetSection("TokenOptions").Get<TokenOptions>();
        }

        [Test]
        public async Task SignAndVerify_WithKeyVault_RS256()
        {
            SynchronizationContext.SetSynchronizationContext(null);
            Environment.SetEnvironmentVariable("AZURE_IDENTITY_LOGGING_ENABLED", "true");
            AzureEventSourceListener listener = AzureEventSourceListener.CreateConsoleLogger();

            if (_oidcOptions == null)
                throw new InvalidOperationException("OidcOptions configuration is missing or invalid.");
            if (_jwtOptions == null)
                throw new InvalidOperationException("TokenOptions configuration is missing or invalid.");

            var credential = new ClientSecretCredential(
                _oidcOptions.TenantID,
                _oidcOptions.ClientID,
                _oidcOptions.ClientSecret,
                new ClientSecretCredentialOptions
                {
                    AuthorityHost = AzureAuthorityHosts.AzurePublicCloud,
                    Retry =
                    {
                        MaxRetries = 0
                    }
                });

            var keyClient = new KeyClient(new Uri(_jwtOptions.KeyVaultUrl), 
                                        credential,
                                        new KeyClientOptions
                                        {
                                            Retry = { NetworkTimeout = TimeSpan.FromSeconds(10) }  // <- иначе висит
                                        });
            
            KeyVaultKey key = await keyClient.GetKeyAsync(_jwtOptions.KeyName);

            var crypto = new CryptographyClient(key.Id, credential);
            var header = new { alg = "RS256", typ = "JWT", kid = key.Id.ToString() };
            var payload = new { sub = "test-sub", iss = "issuer", aud = "aud", exp = 9999999999, iat = 1 };

            string headerJson = JsonSerializer.Serialize(header);
            string payloadJson = JsonSerializer.Serialize(payload);

            string headerEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerJson));
            string payloadEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payloadJson));
            string signingInput = $"{headerEncoded}.{payloadEncoded}";

            // Sign using Key Vault (RS256)
            var signResult = await crypto.SignDataAsync(SignatureAlgorithm.RS256, Encoding.UTF8.GetBytes(signingInput));
            byte[] signature = signResult.Signature;
            string signatureEncoded = Base64UrlEncoder.Encode(signature);

            string jwt = $"{signingInput}.{signatureEncoded}";

            // Verify using Key Vault (public key)
            var verifyResult = await crypto.VerifyDataAsync(SignatureAlgorithm.RS256, Encoding.UTF8.GetBytes(signingInput), signature);

            Assert.True(verifyResult.IsValid, "Key Vault verification failed");
            //Assert.Contains("RS256", headerJson);
            Assert.AreEqual(key.Id.ToString(), header.kid);
        }

    }
}
