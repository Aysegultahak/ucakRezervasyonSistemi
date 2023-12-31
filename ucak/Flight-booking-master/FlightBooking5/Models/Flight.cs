using System.ComponentModel.DataAnnotations;

namespace FlightBooking5.Models
{
    public class Flight
    {
        [Key]
        public int flightId { get; set; }

        [Required(ErrorMessage = "A airline is required to proceed!")]
        public String Airline { get; set; }

        [Required(ErrorMessage = "An aircraft code is required to proceed!")]
        public string AircraftCode { get; set; }

        [Required(ErrorMessage = "An aircraft type is required to proceed!")]
        public string AircraftType { get; set; }

        [Required(ErrorMessage = "A departure country is required to proceed!")]
        public string DepartureCountry { get; set; }

        [Required(ErrorMessage = "A departure country is required to proceed!")]
        public string ArrivalCountry { get; set; }

        [Required(ErrorMessage = "A departure date is required to proceed!")]
        [DataType(DataType.Date)]
        public DateTime DepartureDate { get; set; }

        [Required(ErrorMessage = "A flight status is required to proceed!")]
        public bool FlightStatus { get; set; }

        [Required(ErrorMessage = "A price is required to proceed!")]
        public double Price { get; set; }

        [Required(ErrorMessage = "A Departure Time is required to proceed!")]
        [DataType(DataType.Time)]
        [DisplayFormat(ApplyFormatInEditMode = true, DataFormatString = "{0:hh:mm}")]
        public DateTime DepartureTime { get; set; }

        [Required(ErrorMessage = "A Arrival Time is required to proceed!")]
        [DataType(DataType.Time)]
        [DisplayFormat(ApplyFormatInEditMode = true, DataFormatString = "{0:hh:mm}")]
        public DateTime ArrivalTime { get; set; }

        [Required(ErrorMessage = "A price is required to proceed!")]
        public String Class { get; set; }
        
    }

}
