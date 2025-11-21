using System.CodeDom.Compiler;

namespace midas.Services.OTP
{
    public interface IOTPService
    {
        string Generate();

        // Store OTP and retrieve the OID acociated with it after storing is complete
        bool Save(string userId, 
                  string phoneNumber,
                  string otp);
        
        // Find OID accociated with OTP
        string RetrieveUserId(string code);
    }
}
