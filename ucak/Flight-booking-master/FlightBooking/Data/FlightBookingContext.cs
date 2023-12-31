using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using FlightBooking.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace FlightBooking.Data
{
    public class FlightBookingContext : IdentityDbContext
    {
        public FlightBookingContext (DbContextOptions<FlightBookingContext> options)
            : base(options)
        {
        }

        public DbSet<FlightBooking.Models.Customer> Customer { get; set; } = default!;

        public DbSet<FlightBooking.Models.Flight>? Flight { get; set; }
    }
}
