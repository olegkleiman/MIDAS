using Microsoft.EntityFrameworkCore;
using midas.Models.Tables;
using midas.Services.Db;
using System.Security.Cryptography;
using System.Text;

namespace midas.Services.OTP
{
    public class OTPService(OTPDbContext dbContext) : IOTPService
    {
        readonly OTPDbContext _dbContext = dbContext;

        const int EXPIRE_MIN = 5; // 5 minutes
        const string audience = "midas-api";

        public string Generate()
        {
            uint upperBound = 999999;
            byte[] random = new Byte[sizeof(int)];
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(random);
            uint value = BitConverter.ToUInt32(random, 0);

            int shift = 32 - 20;  // only last 6 digits: 32 - log(upperBound)
            value = value >> shift;
            if (value > upperBound)
            {
                value -= upperBound;
            }

            return value.ToString();
        }

        private static byte[] SHA256_hash(string value)
        {
            Encoding enc = Encoding.UTF8;
            return SHA256.HashData(enc.GetBytes(value));
        }

        public bool Save(string userId,
                        string phoneNumber,
                        string otp)
        {
            _dbContext.Otps.Where(
                    info => info.user_id.Contains(userId)
                 //&& info.otp_exp < DateTime.Now
                 )
                .ExecuteDelete();

            _dbContext.Otps.Add(new UsersOtp()
            {
                user_id = userId,
                phone_number = phoneNumber,
                otp = SHA256_hash(otp),
                otp_exp = DateTime.Now.AddMinutes(EXPIRE_MIN),
                audience = audience,
                plain_otp = otp
            });

            return _dbContext.SaveChanges() > 0;
        }

        public bool SaveRefreshToken(string refreshToken)
        {
            _dbContext.RefreshTokens.Add(new RefreshToken()
            {
                refresh_token = refreshToken
            });

            return _dbContext.SaveChanges() > 0;
        }

        public string RetrieveUserId(string code)
        {
            var storedValue = (_dbContext.Otps.Where(
                info => info.plain_otp != null && info.plain_otp.Contains(code)
                //&& info.otp_exp < DateTime.Now
            )).FirstOrDefault();
            if (storedValue == null)
                return string.Empty;

            return storedValue.user_id;
        }

        public bool IsRefreshTokenValid(string refreshToken)
        {
            var storedValue = (_dbContext.RefreshTokens.Where(
                info => info.refresh_token != null && info.refresh_token.Contains(refreshToken)
            )).FirstOrDefault();
            return storedValue != null;
        }

        public bool DeleteRefreshToken(string refreshToken)
        {
            var storedValue = (_dbContext.RefreshTokens.Where(
                info => info.refresh_token != null && info.refresh_token.Contains(refreshToken)
            )).FirstOrDefault();
            if (storedValue == null)
                return false;
            _dbContext.RefreshTokens.Remove(storedValue);
            return _dbContext.SaveChanges() > 0;
        }

    }
}
