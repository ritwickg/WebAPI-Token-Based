using System.ComponentModel.DataAnnotations;

namespace TokenAuthenticationNetCore.Models
{
    public class RegisterUserModel
    {
        [Required]
        [MinLength(4)]
        public string UserName { get; set; }

        [Required]
        public string FirstName { get; set; }

        [Required]
        public string LastName { get; set; }

        [Required]
        [Range(0, 100, ErrorMessage = "INVALID_AGE")]
        public int Age { get; set; }

        [Required]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "PASSWORD_MIN_LENGTH", MinimumLength = 6)]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password))]
        public string ConfirmPassword { get; set; }  
    }
}
