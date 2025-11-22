
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Jose;
using Microsoft.Extensions.Options;
using midas.Services.JWT;
using System.Security.Cryptography;
using System.Text;

namespace midas.Services.Oid
{
    public class OidService(IOptions<TokenOptions> jwtOptions,
                            IOptions<OidcOptions> oidcOptions) : IOidService
    {
        SecretClient? _secretClient = null;

        private readonly OidcOptions _oidcOptions = oidcOptions.Value;
        private readonly TokenOptions _jwtOptions = jwtOptions.Value;

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

        public string RetrieveOID(string userId)
        {
            return EncryptString(userId);
        }

        public string RetrieveUserId(string oid)
        {
            return DecryptString(oid);
        }
        public string EncryptString(string text)
        {

            _secretClient ??= new(new Uri(_jwtOptions.KeyVaultUrl), _credentials);
            var _jweKey = _secretClient.GetSecret(_jwtOptions.OidSecretName);
            var keyBytes = Encoding.UTF8.GetBytes(_jweKey.Value.Value);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = keyBytes;
                aesAlg.GenerateIV();
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream ms = new())
                {
                    // Write IV first
                    ms.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                    using (CryptoStream cs = new(ms, encryptor, CryptoStreamMode.Write))
                    using (StreamWriter sw = new(cs))
                    {
                        sw.Write(text);
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        public string DecryptString(string cipherText)
        {
            _secretClient ??= new(new Uri(_jwtOptions.KeyVaultUrl), _credentials);
            var _jweKey = _secretClient.GetSecret(_jwtOptions.OidSecretName);
            var keyBytes = Encoding.UTF8.GetBytes(_jweKey.Value.Value);

            byte[] fullCipher = Convert.FromBase64String(cipherText);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = keyBytes;

                byte[] iv = new byte[aesAlg.BlockSize / 8];
                Array.Copy(fullCipher, 0, iv, 0, iv.Length);
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream ms = new(fullCipher, iv.Length, fullCipher.Length - iv.Length))
                using (CryptoStream cs = new(ms, decryptor, CryptoStreamMode.Read))
                using (StreamReader sr = new(cs))
                {
                    return sr.ReadToEnd();
                }
            }
        }

    }
}
