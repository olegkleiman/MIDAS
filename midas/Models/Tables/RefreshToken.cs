using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace midas.Models.Tables
{
    [Table(name: "refresh_tokens")]
    public record RefreshToken
    {
        [Key]
        public int id { get; set; }
        public required string refresh_token { get; set; }
    }   

    [Table(name: "users_otp")]
    public record UsersOtp
    {
        [Key]
        public int id { get; set; }
        public string user_id { get; set; }
        public string? phone_number { get; set; }
        public byte[]? otp { get; set; }
        public DateTime? otp_exp { get; set; }
        public string? plain_otp { get; set; }
        public string? audience { get; set; }
    }
}
