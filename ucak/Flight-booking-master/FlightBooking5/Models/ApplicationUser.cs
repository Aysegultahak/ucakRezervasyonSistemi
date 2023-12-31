using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
namespace FlightBooking5.Models

{
    public class ApplicationUser: IdentityUser
    {
        [Required(ErrorMessage = "Enter first name")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "Enter last name")]
        public string LastName { get; set; }
        [Required(ErrorMessage = "Enter birthdate")]
        [DataType(DataType.Date)]
        public DateTime DateOfBirth { get; set; }

        [Required(ErrorMessage = "Enter gender type")]
        public string Gender { get; set; }
       
       
    }
}
