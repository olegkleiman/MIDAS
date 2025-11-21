using System.ComponentModel.DataAnnotations;

namespace midas.Models
{
    public class VerifyFormData
    {
        [Required]
        public string token { get; set; }
    }
}
