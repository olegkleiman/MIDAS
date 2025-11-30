using System.CodeDom.Compiler;

namespace midas.Services.OTP
{
    public interface IOTPService
    {
        string Generate();

        // Store user_id and return the operation resut
        bool Save(string userId, 
                  string phoneNumber,
                  string otp);
        
        // Find OID accociated with OTP
        string RetrieveUserId(string otp);
        bool SaveRefreshToken(string refreshToken);
        bool IsRefreshTokenValid(string refreshToken);
        bool DeleteRefreshToken(string refreshToken);
    }
}
