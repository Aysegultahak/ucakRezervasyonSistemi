using FlightBooking5.Data;
using FlightBooking5.Infrastructure;
using FlightBooking5.Models;
using Microsoft.AspNetCore.Components.RenderTree;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using NuGet.Protocol.Core.Types;
using PayPal.Api;
using System.Collections.Generic;
using System.Configuration;

namespace FlightBooking5.Controllers
{
    public class CartController : Controller
    {
        public Cart? Cart { get; set; }
        private readonly FlightBooking5Context _context;
        private IConfiguration _configuration;
        public CartController(FlightBooking5Context context, IConfiguration IConfiguration)
        {
            _context = context;
            _configuration = IConfiguration;
        }
		public IActionResult ViewCart()
		{
			Cart = HttpContext.Session.GetJson<Cart>("cart") ?? new Cart();
			return View("cart", Cart);
		}
        public IActionResult UpdateCart(int flightId)
        {
            Flight? flight = _context.Flight
            .FirstOrDefault(f => f.flightId == flightId);
            if (flight != null)
            {
                Cart = HttpContext.Session.GetJson<Cart>("cart") ?? new Cart();
                Cart.AddItem(flight, -1);
                HttpContext.Session.SetJson("cart", Cart);
            }

            return View("cart", Cart);
        }
        public IActionResult AddToCart(int flightId)
        {
            Flight? flight = _context.Flight
            .FirstOrDefault(f => f.flightId == flightId);
            if (flight != null)
            {
                Cart = HttpContext.Session.GetJson<Cart>("cart") ?? new Cart();
                Cart.AddItem(flight, 1);
                HttpContext.Session.SetJson("cart", Cart);
            }

            return View("cart", Cart);
        }
        public IActionResult RemoveFromCart(int flightId)
        {
            Flight? flight = _context.Flight
            .FirstOrDefault(f => f.flightId == flightId);
            if (flight != null)
            {
                Cart = HttpContext.Session.GetJson<Cart>("cart") ?? new Cart();
                Cart.RemoveLine(flight);
                HttpContext.Session.SetJson("cart", Cart);
            }

            return View("cart", Cart);
        }
        public IActionResult RemoveAllFromCart()
        {
            Cart = new Cart();
            HttpContext.Session.SetJson("cart", Cart);
            return RedirectToAction("Index", "Home");
        }

    }
}
   

