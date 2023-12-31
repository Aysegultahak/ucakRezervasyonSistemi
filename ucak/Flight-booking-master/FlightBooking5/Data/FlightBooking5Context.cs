using FlightBooking5.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace FlightBooking5.Data
{
    public class FlightBooking5Context : IdentityDbContext
    {
        public FlightBooking5Context(DbContextOptions<FlightBooking5Context> options)
            : base(options)
        {
        }

        

        public DbSet<FlightBooking5.Models.Flight>? Flight { get; set; }
		public DbSet<FlightBooking5.Models.PaymentDetails> PaymentDetails { get; set; }
        public DbSet<ApplicationUser> ApplicationUsers { get; set; } 
        public DbSet<FlightBooking5.Models.ImageAd>? ImageAd { get; set; }
        public DbSet<FlightBooking5.Models.Employee>? Employee { get; set; }
	}
}
