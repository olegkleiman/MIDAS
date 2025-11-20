using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace midas.Services.JWT
{
    public class KeyVaultRsaSecurityKey : RsaSecurityKey
    {
        public string KeyId { get; }

        public KeyVaultRsaSecurityKey(string keyVaultKeyIdentifier)
            : base(RSA.Create()) // RSA не используется для подписи, но нужен базовому классу
        {
            KeyId = keyVaultKeyIdentifier;
            base.KeyId = keyVaultKeyIdentifier;
        }
    }
}
