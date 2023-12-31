using System.ComponentModel.DataAnnotations;

namespace FlightBooking.Models
{
    public class Flight
    {

        [Key]
        public int flightId { get; set; }

        [Required(ErrorMessage = "An aircraft code is required to proceed!")]
        public string aircraftCode { get; set; }

        [Required(ErrorMessage = "An aircraft type is required to proceed!")]
        public string aircraftType { get; set; }

        [Required(ErrorMessage = "A departure country is required to proceed!")]
        public string departureCountry { get; set; }


        public string arrivalCountry { get; set; }

        [Required(ErrorMessage = "A departure date is required to proceed!")]
        [DataType(DataType.Date)]

        public DateTime departureDate { get; set; }

        [Required(ErrorMessage = "An arrival date is required to proceed!")]
       
        public DateTime arrivalDate { get; set; }

        [Required(ErrorMessage = "A flight status is required to proceed!")]
        public bool flightStatus { get; set; }
        [Required(ErrorMessage = "A price is required to proceed!")]
        public double price { get; set; }
    }
}
