using System.ComponentModel.DataAnnotations;

namespace JWT.Models
{
    public class ApplicationUser : IdentityUser
    {
        [MaxLength(50, ErrorMessage ="Invalid name")]
        public string FirstName { get; set; }
        [MaxLength(50, ErrorMessage = "Invalid name")]
        public string LastName { get; set; }
    }
}
