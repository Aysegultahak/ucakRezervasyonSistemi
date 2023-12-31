using FlightBooking5.Data;
using FlightBooking5.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace FlightBooking5.Controllers
{
    public class FlightsController : Controller
    {
        private readonly FlightBooking5Context _context;

        public FlightsController(FlightBooking5Context context)
        {
            _context = context;
        }

        // GET: Flights
        [Authorize(Roles = "Admin Manager")]
        public async Task<IActionResult> Index()
        {
            return _context.Flight != null ?
                        View(await _context.Flight.ToListAsync()) :
                        Problem("Entity set 'FlightBooking5Context.Flight'  is null.");
        }
        // GET: Flights/Search
        public IActionResult Search(string departureCountry, string arrivalCountry, DateTime departureDate, String Class)
        {
            var flights = _context.Flight
                .Where(f => f.DepartureCountry == departureCountry && f.ArrivalCountry == arrivalCountry && f.FlightStatus == true && f.DepartureDate == departureDate && f.Class == Class)
                .ToList();

            return View(flights);
        }
        // GET: Flights/Details/5
        [Authorize(Roles = "Admin Manager")]
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null || _context.Flight == null)
            {
                return NotFound();
            }

            var flight = await _context.Flight
                .FirstOrDefaultAsync(m => m.flightId == id);
            if (flight == null)
            {
                return NotFound();
            }

            return View(flight);
        }
        [Authorize(Roles = "Admin Manager")]
        // GET: Flights/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Flights/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("flightId,AircraftCode,AircraftType,DepartureCountry,ArrivalCountry,DepartureDate,FlightStatus,Price,DepartureTime,ArrivalTime,Class,Airline")] Flight flight)
        {
            if (ModelState.IsValid)
            {
                _context.Add(flight);
                await _context.SaveChangesAsync();
                return RedirectToAction("AddFlight", "Admin");
            }
            return View(flight);
        }

        // GET: Flights/Edit/5
        [Authorize(Roles = "Admin Manager")]
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null || _context.Flight == null)
            {
                return NotFound();
            }

            var flight = await _context.Flight.FindAsync(id);
            if (flight == null)
            {
                return NotFound();
            }
            return View(flight);
        }

        // POST: Flights/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("flightId,AircraftCode,AircraftType,DepartureCountry,ArrivalCountry,DepartureDate,FlightStatus,Price,DepartureTime,ArrivalTime,Class,Airline")] Flight flight)
        {
            if (id != flight.flightId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(flight);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!FlightExists(flight.flightId))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction("AddFlight", "Admin");
            }
            return View(flight);
        }

        // GET: Flights/Delete/5
        [Authorize(Roles = "Admin Manager")]
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null || _context.Flight == null)
            {
                return NotFound();
            }

            var flight = await _context.Flight
                .FirstOrDefaultAsync(m => m.flightId == id);
            if (flight == null)
            {
                return NotFound();
            }

            return View(flight);
        }

        // POST: Flights/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
       
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            if (_context.Flight == null)
            {
                return Problem("Entity set 'FlightBooking5Context.Flight'  is null.");
            }
            var flight = await _context.Flight.FindAsync(id);
            if (flight != null)
            {
                _context.Flight.Remove(flight);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction("AddFlight", "Admin");
        }

        private bool FlightExists(int id)
        {
            return (_context.Flight?.Any(e => e.flightId == id)).GetValueOrDefault();
        }
    }
}
