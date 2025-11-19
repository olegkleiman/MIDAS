using System.Security.Cryptography;

namespace midas.Services.OTP
{
    public class OTPService : IOTPService
    {
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
    }
}
