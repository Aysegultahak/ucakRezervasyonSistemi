using FlightBooking5.Data;
using FlightBooking5.Models;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace FlightBooking5.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly FlightBooking5Context _context;

        public HomeController(ILogger<HomeController> logger, FlightBooking5Context context)
        {
            _logger = logger;
            _context = context;
        }
        

      
        public IActionResult Index()
        {
            var imageAds = _context.ImageAd.ToList();
            return View(imageAds);
           
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}