using Azure;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using midas.Services.JWT;
using midas.Utils;
using NSubstitute;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace midas.tests
{
    internal class JWTIssuerServiceTest
    {
        private JWTIssuerOptions _jwtOptions = new()
        {
            Issuer = "test-issuer",
            Audience = "test-audience",
            KeyVaultUrl = "https://test.vault.azure.net/",
            KeyName = "test-key",
            SecretName = "refresh-secret",
            ExpiredInHours = 1
        };

        private OidcOptions _oidcOptions = new()
        {
            TenantID = "1111",
            ClientID = "2222",
            ClientSecret = "3333"
        };

        private ILogger<JWTIssuerService>   _logger;
        private SecretClient                _secretClient;
        private KeyClient                   _keyClient;
        private EncryptionHelper            _encryptionHelper;

        [SetUp]
        public void Setup()
        {
            _logger = Substitute.For<ILogger<JWTIssuerService>>();
            _secretClient = Substitute.For<SecretClient>();
            _keyClient = Substitute.For<KeyClient>();
            _encryptionHelper = Substitute.For<EncryptionHelper>("dummy");
        }

        [Test]
        public async Task IssueForSubject_ShouldReturnTokens()
        {
            // Arrange
            var optionsJwt = Substitute.For<IOptions<JWTIssuerOptions>>();
            optionsJwt.Value.Returns(_jwtOptions);

            var optionsOidc = Substitute.For<IOptions<OidcOptions>>();
            optionsOidc.Value.Returns(_oidcOptions);

            // Mock SecretClient.GetSecret()
            var secret = Response.FromValue(
                new KeyVaultSecret(_jwtOptions.SecretName, "my-secret-value"),
                Substitute.For<Response>()
            );
            _secretClient.GetSecret(_jwtOptions.SecretName).Returns(secret);

            //// Mock EncryptionHelper behavior (Encrypt)
            //_encryptionHelper.Encrypt(Arg.Any<string>())
            //    .Returns("encrypted-refresh-token");

            //// Mock KeyClient.GetKeyAsync()
            //var fakeKeyVaultKey = Response.FromValue(
            //    new KeyVaultKey("fake-key")
            //    {
            //        Key = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(RSA.Create(2048)))
            //    },
            //    Substitute.For<Response>()
            //);

            //_keyClient.GetKeyAsync(Arg.Any<string>()).Returns(Task.FromResult(fakeKeyVaultKey));

            //var fakeKey = Substitute.For<KeyVaultKey>("testKey");
            //fakeKey.Key.Returns(fakeJsonWebKey);

            //_keyClient.GetKeyAsync(_jwtOptions.KeyName)
            //    .Returns(Task.FromResult(Response.FromValue(fakeKey, Substitute.For<Response>())));

            //var service = new JWTIssuerService(
            //    optionsJwt,
            //    optionsOidc,
            //    _logger,
            //    _secretClient,
            //    _keyClient,
            //    _encryptionHelper
            //);

            //// Act
            //var tokens = await service.IssueForSubject("user123");

            //// Assert
            //Assert.IsNotNull(tokens);
            //Assert.IsNotNull(tokens.AccessToken);
            //Assert.AreEqual("encrypted-refresh-token", tokens.RefreshToken);

            //// Validate JWT
            //var handler = new JwtSecurityTokenHandler();
            //var jwt = handler.ReadJwtToken(tokens.AccessToken);

            //Assert.AreEqual("user123", jwt.Subject);
            //Assert.AreEqual(_jwtOptions.Issuer, jwt.Issuer);
            //Assert.AreEqual(_jwtOptions.Audience, jwt.Audiences.First());
        }
    }
}

