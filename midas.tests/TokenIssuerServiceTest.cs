using Azure;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using midas.Services.JWT;
using midas.Utils;
using NSubstitute;

namespace midas.tests
{
    internal class TokenIssuerServiceTest
    {
        private OidcOptions? _oidcOptions;
        private TokenOptions? _tokenOptions;

        private ILogger<TokenService>? _logger;
        private SecretClient? _secretClient;
        private KeyClient? _keyClient;
        private EncryptionHelper? _encryptionHelper;

        [SetUp]
        public void Setup()
        {
            var configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.Development.json")
                .Build();

            _oidcOptions = configuration.GetSection("OidcOptions").Get<OidcOptions>();
            _tokenOptions = configuration.GetSection("TokenOptions").Get<TokenOptions>();

            _logger = Substitute.For<ILogger<TokenService>>();
            _secretClient = Substitute.For<SecretClient>();
            _keyClient = Substitute.For<KeyClient>();
            _encryptionHelper = Substitute.For<EncryptionHelper>("dummy");
        }

        [Test]
        public void IssueForSubject_ShouldReturnTokens()
        {
            // Arrange
            var optionsJwt = Substitute.For<IOptions<TokenOptions>>();
            optionsJwt.Value.Returns(_tokenOptions);

            var optionsOidc = Substitute.For<IOptions<OidcOptions>>();
            optionsOidc.Value.Returns(_oidcOptions);

            // Mock SecretClient.GetSecret()
            var secret = Response.FromValue(
                new KeyVaultSecret(_tokenOptions.OidSecretName, "my-secret-value"),
                Substitute.For<Response>()
            );
            _secretClient.GetSecret(_tokenOptions.OidSecretName).Returns(secret);

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

            //var service = new TokenService(
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

