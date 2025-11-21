
using System.Security.Cryptography;
using System.Text;

namespace midas.Services.Oid
{
    public class OidService : IOidService
    {
        string password = "abcdefgh";

        public string RetrieveOID(string userId)
        {
            return EncryptString(userId, password);
        }

        public string RetrieveUserId(string oid)
        {
            return DecryptString(oid, password);
        }
        public static string EncryptString(string text, string password)
        {
            byte[] key = SHA256.HashData(Encoding.UTF8.GetBytes(password));
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
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

        public static string DecryptString(string cipherText, string password)
        {
            byte[] fullCipher = Convert.FromBase64String(cipherText);
            byte[] key = SHA256.HashData(Encoding.UTF8.GetBytes(password));

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;

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
