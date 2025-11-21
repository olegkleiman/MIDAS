using System.ComponentModel.DataAnnotations;

namespace midas.Models
{
    public class RefreshTokenFormData
    {
        [Required]
        public required string refresh_token { get; set; }
    }
}
