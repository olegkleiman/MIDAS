using System.ComponentModel.DataAnnotations;

namespace midas.Models
{
    public record OTPDto
    {
        /// <summary>
        ///  Generated OTP
        /// </summary>
        [Required]
        public required string code { get; set; }
    }
}
