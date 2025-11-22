using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Secrets;
using Jose;
using Microsoft.Extensions.Options;

using Microsoft.IdentityModel.Tokens;
using midas.Models;
using midas.Utils;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace midas.Services.JWT
{
    public class TokenService(IOptions<TokenOptions> jwtOptions,
                                  IOptions<OidcOptions> oidcOptions,
                                  ILogger<TokenService> logger) : ITokenService

    {
        private readonly TokenOptions _jwtOptions = jwtOptions.Value;
        private readonly OidcOptions _oidcOptions = oidcOptions.Value;
        private readonly ILogger<TokenService> _logger = logger;

        SecretClient? _secretClient = null;
        KeyClient? _keyClient = null;
        EncryptionHelper? _encryptionHelper = null;

        private readonly DateTime _epoch = new(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public ClientSecretCredential _credentials => new(
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
            }
        );

        private string CreateRefreshToken(string oid)
        {
            _secretClient ??= new(new Uri(_jwtOptions.KeyVaultUrl), _credentials);

            try
            {
                KeyVaultSecret secret = _secretClient.GetSecret(_jwtOptions.RefreshTokenSecretName);
                EncryptionHelper encryptionHelper = _encryptionHelper ??
                                                    new(secret.Value);
                long exp = (long)(DateTime.UtcNow.AddDays(60) - _epoch).TotalSeconds;
                return encryptionHelper.Encrypt($"{oid};{exp}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to create refresh token: {ex.Message}");
            }

            return string.Empty;
        }

        public async Task<AuthTokens> IssueJWEForSubject(string subject)
        {
            long exp = (long)(DateTime.UtcNow.AddHours(_jwtOptions.ExpiredInHours) - _epoch).TotalSeconds;
            long iat = (long)(DateTime.UtcNow - _epoch).TotalSeconds;
            long nbf = iat;

            var payload = new Dictionary<string, object>
            {
                { JwtRegisteredClaimNames.Sub, subject },
                { JwtRegisteredClaimNames.Iss, _jwtOptions.Issuer },
                { JwtRegisteredClaimNames.Aud, _jwtOptions.Audience },
                { JwtRegisteredClaimNames.Exp, exp },
                { JwtRegisteredClaimNames.Iat, iat },
                { JwtRegisteredClaimNames.Nbf, nbf }
            };

            _keyClient ??= new(new Uri(_jwtOptions.KeyVaultUrl), _credentials);
            KeyVaultKey kvKey = await _keyClient.GetKeyAsync(_jwtOptions.KeyName);
            
            // Theoretically, Azure KV could return the kvKey that is not RSA
            if( kvKey.KeyType != KeyType.Rsa && kvKey.KeyType != KeyType.RsaHsm )
            {
                throw new InvalidOperationException("The specified kvKey is not an RSA kvKey.");
            }

            RSA rsaPublic = kvKey.Key.ToRSA(); // encryption based only on public kvKey

            // TODO:
            // create compact JWE (alg=RSA-OAEP-256, enc=A256GCM)
            string jwe = Jose.JWT.Encode(payload,
                                rsaPublic,
                                JweAlgorithm.RSA_OAEP,
                                JweEncryption.A256GCM);
            // JWE consists of 5 parts : header.encryptedKey.iv.ciphertext.authTag

            return new AuthTokens()
            {
                AccessToken = jwe,
                RefreshToken = CreateRefreshToken(subject)
            };
        }

        public async Task<Dictionary<string, object>?> DecryptJWE(string jwe)
        {
            // 1. Получаем ссылку на ключ (не сам ключ)
            _keyClient ??= new(new Uri(_jwtOptions.KeyVaultUrl), _credentials);
            KeyVaultKey key = await _keyClient.GetKeyAsync(_jwtOptions.KeyName);

            // 2. Create CryptographyClient because the private kvKey should never leaves the Key Vault
            // and we will pass the payload to there 
            var cryptoClient = new CryptographyClient(key.Id, _credentials);

            // 3. Парсим JWE вручную (jose-jwt делает это внутри, но нам нужен CEK)
            var parts = jwe.Split('.');
            if (parts.Length != 5)
                throw new InvalidOperationException("Invalid JWE format.");

            string protectedHeaderEncoded = parts[0];   // header (base64url)
            string encryptedKeyB64Url = parts[1];   // encrypted CEK
            string ivB64Url = parts[2];   // iv (nonce)
            string ciphertextB64Url = parts[3];   // ciphertext
            string tagB64Url = parts[4];   // auth tag

            byte[] encryptedCek = Jose.Base64Url.Decode(encryptedKeyB64Url);
            byte[] iv = Jose.Base64Url.Decode(ivB64Url);
            byte[] ciphertext = Jose.Base64Url.Decode(ciphertextB64Url);
            byte[] tag = Jose.Base64Url.Decode(tagB64Url);

            // 4. Decrypt CEK via Key Vault (RSA-OAEP-256)
            var decryptResult = await cryptoClient.DecryptAsync(
                EncryptionAlgorithm.RsaOaep,
                encryptedCek);
            byte[] cek = decryptResult.Plaintext; // this is the symmetric AES kvKey (should be 32 bytes for A256GCM)

            // 5. Now decrypt AES-GCM:
            // AesGcm expects ciphertext and tag separately. We have both.
            // AssociatedData (AAD) should be the protected header bytes (original base64url header bytes)
            byte[] aad = Encoding.UTF8.GetBytes(protectedHeaderEncoded);
            byte[] decrypted = new byte[ciphertext.Length];

            try
            {
                using var aesGcm = new System.Security.Cryptography.AesGcm(cek);
                aesGcm.Decrypt(iv, ciphertext, tag, decrypted, aad);
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine("AES-GCM decryption failed: " + ex.Message);
                throw;
            }

            // Convert JSON → Dictionary<string, object>
            return System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(decrypted);
        }

        public async Task<Dictionary<string, object>> ValidateJweToken(string jwe)
        {
            var claims = await DecryptJWE(jwe);
            if (!ValidateLifetime(claims))
                throw new SecurityTokenExpiredException("The token is expired or not yet valid.");

            if (!ValidateIssuerAndAudience(claims))
                throw new SecurityTokenInvalidIssuerException("Issuer or audience mismatch.");

            return claims;
        }

        private bool ValidateLifetime(Dictionary<string, object> claims)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (claims.TryGetValue(JwtRegisteredClaimNames.Exp, out object? expObj))
            {
                long exp = GetLongFromPayload(expObj);
                if (now >= exp)
                    return false; // expired
            }
            else
            {
                throw new Exception("'exp' claim is missing from token");
            }

            if (claims.TryGetValue(JwtRegisteredClaimNames.Nbf, out object? nbfObj))
            {
                long nbf = GetLongFromPayload(nbfObj);

                if (now < nbf)
                    return false; // token not active yet
            }

            if (claims.TryGetValue(JwtRegisteredClaimNames.Iat, out object? iatObj))
            {
                long iat = GetLongFromPayload(iatObj);

                if (iat > now + 30) // token issued in the future? (skew 30s)
                    return false;
            }

            return true;

        }

        private static long GetLongFromPayload(object value)
        {
            if (value is long l)
                return l;

            if (value is int i)
                return i;

            if (value is JsonElement je)
            {
                if (je.ValueKind == JsonValueKind.Number)
                    return je.GetInt64();

                if (je.ValueKind == JsonValueKind.String &&
                    long.TryParse(je.GetString(), out long parsed))
                    return parsed;
            }

            throw new InvalidCastException($"Cannot convert value '{value}' to long.");
        }

        private bool ValidateIssuerAndAudience(Dictionary<string, object> payload)
        {
            if (!payload.TryGetValue(JwtRegisteredClaimNames.Iss, out var issObj)
                || !payload.TryGetValue(JwtRegisteredClaimNames.Aud, out var audObj))
                return false;

            string iss = issObj.ToString()!;
            string aud = audObj.ToString()!;

            if (iss != _jwtOptions.Issuer)
                return false;

            if (aud != _jwtOptions.Audience)
                return false;

            return true;
        }

        public async Task<AuthTokens> IssueForSubject(string subject)
        {
            var refreshToken = CreateRefreshToken(subject);

            _keyClient ??= new(new Uri(_jwtOptions.KeyVaultUrl), _credentials);
            KeyVaultKey key = await _keyClient.GetKeyAsync(_jwtOptions.KeyName);

            // Use CryptographyClient to sign with Key Vault private kvKey (RS256)
            var cryptoClient = new CryptographyClient(key.Id, _credentials);
            long exp = (long)(DateTime.UtcNow.AddHours(_jwtOptions.ExpiredInHours) - _epoch).TotalSeconds;
            long iat = (long)(DateTime.UtcNow - _epoch).TotalSeconds;

            var header = new Dictionary<string, object>
            {
                { "alg", "RS256" },
                { "typ", "JWT" },
                { "kid", key.Id.ToString() }
            };
            var payload = new Dictionary<string, object>
            {
                { JwtRegisteredClaimNames.Sub, subject },
                { JwtRegisteredClaimNames.Iss, _jwtOptions.Issuer },
                { JwtRegisteredClaimNames.Aud, _jwtOptions.Audience },
                { JwtRegisteredClaimNames.Exp, exp },
                { JwtRegisteredClaimNames.Iat, iat }
            };
            string headerJson = JsonSerializer.Serialize(header);
            string payloadJson = JsonSerializer.Serialize(payload);

            string headerEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerJson));
            string payloadEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payloadJson));

            string signingInput = $"{headerEncoded}.{payloadEncoded}";

            // Sign the signingInput using Key Vault (RS256)
            var signResult = await cryptoClient.SignDataAsync(
                                    SignatureAlgorithm.RS256,
                                    Encoding.UTF8.GetBytes(signingInput)
            );
            string signatureEncoded = Base64UrlEncoder.Encode(signResult.Signature);

            string jwt = $"{signingInput}.{signatureEncoded}";

            return new AuthTokens()
            {
                AccessToken = jwt,
                RefreshToken = refreshToken
            };
        }

        public async Task<IEnumerable<Claim>> VerifyJWT(string token)
        {
            _secretClient ??= new(new Uri(_jwtOptions.KeyVaultUrl), _credentials);

            KeyClient keyClient = _keyClient ??
                new(new Uri(_jwtOptions.KeyVaultUrl), _credentials);
            KeyVaultKey key = await keyClient.GetKeyAsync(_jwtOptions.KeyName);

            var tokenHandler = new JwtSecurityTokenHandler();

            TokenValidationParameters validationParams = new()
            {
                ValidateIssuer = true,
                ValidIssuer = _jwtOptions.Issuer,
                ValidateAudience = true,
                ValidAudience = _jwtOptions.Audience,
                ValidateLifetime = true,
                ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
                ValidateIssuerSigningKey = true,
                IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
                {
                    try
                    {
                        var keyUri = new Uri(kid);

                        // segments: ["/", "keys/", "{keyName}/", "{version}"]
                        string keyName = keyUri.Segments.Length > 2 ? keyUri.Segments[2].TrimEnd('/') : _jwtOptions.KeyName;
                        string keyVersion = keyUri.Segments.Length > 3 ? keyUri.Segments[3].TrimEnd('/') : "";

                        // Synchronously fetch the specific kvKey version from Key Vault
                        var keyResponse = keyClient.GetKey(keyName, keyVersion);
                        var resolvedKey = keyResponse.Value;

                        var rsa = resolvedKey.Key.ToRSA();
                        SecurityKey rsaKey = new RsaSecurityKey(rsa)
                        {
                            KeyId = kid
                        };

                        return new List<SecurityKey> { rsaKey };
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Failed to resolve signing kvKey for kid '{kid}': {ex.Message}");
                        return new List<SecurityKey>();
                    }
                }
            };
            ClaimsPrincipal principal = tokenHandler.ValidateToken(token, validationParams, out _);

            return principal.Claims;
        }
    }
}
