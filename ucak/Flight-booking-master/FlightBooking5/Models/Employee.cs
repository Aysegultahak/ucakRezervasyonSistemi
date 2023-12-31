using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FlightBooking5.Models
{
    public class Employee
    {
        [Key]
        public int EmployeeId { get; set; }
        public string Name { get; set; }

        [ForeignKey("flightId")]
        public string flightId { get; set; }
        [NotMapped]
        public List<int> Flights { get; set; }
        public Employee()
        {
            Flights = new List<int>(); // Khởi tạo danh sách Flights trong constructor
        }
    }
}
