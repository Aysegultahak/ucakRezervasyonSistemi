using System.ComponentModel.DataAnnotations;

namespace FlightBooking.Models
{
    public class Customer
    {
        [Key]
        public int customerId { get; set; }

        [Required(ErrorMessage = "Enter first name")]
        public string firstName { get; set; }

        [Required(ErrorMessage = "Enter last name")]
        public string lastName { get; set; }

        [Required(ErrorMessage = "Enter Email adress")]
        public string email { get; set; }

        [Required(ErrorMessage = "Enter phone number")]
        public string phoneNumber { get; set; }

        [Required(ErrorMessage = "Enter birthdate")]
        public DateTime dateOfBirth { get; set; }

        [Required(ErrorMessage = "Enter gender type")]
        public string gender { get; set; }

        [Required(ErrorMessage = "Enter password")]
        [DataType(DataType.Password)]
        public string password { get; set; }

        [DataType(DataType.Password)]
        [Compare("password", ErrorMessage = "Confirm password doesn't match")]
        public string confirmPassword { get; set; }
    }
}
