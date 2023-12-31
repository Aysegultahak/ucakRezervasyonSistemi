using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using FlightBooking5.Data;
using FlightBooking5.Models;
using static System.Net.Mime.MediaTypeNames;
using Microsoft.AspNetCore.Identity;
using System.Data;
using Microsoft.AspNetCore.Authorization;


namespace FlightBooking5.Controllers
{
    public class EmployeesController : Controller
    {
        private readonly FlightBooking5Context _context;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public EmployeesController(FlightBooking5Context context, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _context = context;
            _userManager = userManager;
            _roleManager= roleManager;
    }


        //GET: Employees/CheckSchedule
        [Authorize(Roles="Employee")]
        public IActionResult CheckSchedule()
        {
            string userName = User.Identity.Name;

            var user = _userManager.FindByNameAsync(userName).Result;

            if (user != null)
            {
                bool isEmployee = _userManager.IsInRoleAsync(user, "Employee").Result;

                if (isEmployee)
                {
                    var employee = _context.Employee.FirstOrDefault(e => e.Name == user.UserName);

                    if (employee != null)
                    {
                        var schedule = _context.Flight
                            .Where(f => f.flightId.ToString() == employee.flightId)
                            .FirstOrDefault();

                        if (schedule != null)
                        {
                            // Return the view to display the flight information
                            return View(schedule);
                        }
                    }
                }
            }

            // Return a view to display a message if the schedule is not found or the user doesn't have the "Employee" role
            return View("NotFound");
        }

        //GET:Employees/ChangeRole


        [Authorize(Roles = "Admin Manager")]
        // GET: Employees
        public async Task<IActionResult> Index()
        {
              return _context.Employee != null ? 
                          View(await _context.Employee.ToListAsync()) :
                          Problem("Entity set 'FlightBooking5Context.Employee'  is null.");
        }
        [Authorize(Roles = "Admin Manager")]
        // GET: Employees/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null || _context.Employee == null)
            {
                return NotFound();
            }

            var employee = await _context.Employee
                .FirstOrDefaultAsync(m => m.EmployeeId == id);
            if (employee == null)
            {
                return NotFound();
            }

            return View(employee);
        }

        
        private List<int> GetFlightIds()
        {

            List<int> flightIds = _context.Flight.Select(f => f.flightId).ToList();


            if (flightIds == null)
            {
                flightIds = new List<int>(); // Khởi tạo danh sách rỗng nếu flightIds là null
            }

            return flightIds;
        }




        // GET: Employees/Create

        [Authorize(Roles = "Admin Manager")]
        public IActionResult Create()
        {
            List<int> flightIds = GetFlightIds(); // Lấy danh sách FlightId từ nguồn dữ liệu

            if (flightIds == null)
            {
                flightIds = new List<int>(); // Khởi tạo danh sách rỗng nếu flightIds là null
            }
            ViewBag.Flights = flightIds;

            var employees = _userManager.GetUsersInRoleAsync("Employee").Result;
            var employeeNames = employees.Select(u => new SelectListItem
            {
                
                Text = u.UserName
            }).ToList();

            ViewBag.EmployeeNames = employeeNames ?? new List<SelectListItem>();


            return View();

        }
        // POST: Employees/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("EmployeeId,Name,flightId")] Employee employee)
        {
          
           
            if (ModelState.IsValid)
            {
                _context.Add(employee);
                await _context.SaveChangesAsync();
                return RedirectToAction("EmployeeAssignment", "Admin");
            }
            
            return View(employee);
        }

        // GET: Employees/Edit/5
        [Authorize(Roles = "Admin Manager")]
        public async Task<IActionResult> Edit(int? id)
        {
            List<int> flightIds = GetFlightIds(); // Lấy danh sách FlightId từ nguồn dữ liệu

            if (flightIds == null)
            {
                flightIds = new List<int>(); // Khởi tạo danh sách rỗng nếu flightIds là null
            }
            ViewBag.Flights = flightIds;

            var employees = _userManager.GetUsersInRoleAsync("Employee").Result;
            var employeeNames = employees.Select(u => new SelectListItem
            {
                
                Text = u.UserName
            }).ToList();

            ViewBag.EmployeeNames = employeeNames ?? new List<SelectListItem>();

            if (id == null || _context.Employee == null)
            {
                return NotFound();
            }

            var employee = await _context.Employee.FindAsync(id);
            if (employee == null)
            {
                return NotFound();
            }
            return View(employee);
        }

        // POST: Employees/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("EmployeeId,Name,flightId")] Employee employee)
        {
            if (id != employee.EmployeeId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(employee);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!EmployeeExists(employee.EmployeeId))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction("EmployeeAssignment", "Admin");
            }
            return View(employee);
        }

        // GET: Employees/Delete/5
        [Authorize(Roles = "Admin Manager")]
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null || _context.Employee == null)
            {
                return NotFound();
            }

            var employee = await _context.Employee
                .FirstOrDefaultAsync(m => m.EmployeeId == id);
            if (employee == null)
            {
                return NotFound();
            }

            return View(employee);
        }

        // POST: Employees/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            if (_context.Employee == null)
            {
                return Problem("Entity set 'FlightBooking5Context.Employee'  is null.");
            }
            var employee = await _context.Employee.FindAsync(id);
            if (employee != null)
            {
                _context.Employee.Remove(employee);
            }
            
            await _context.SaveChangesAsync();
            return RedirectToAction("EmployeeAssignment", "Admin");
        }

        private bool EmployeeExists(int id)
        {
          return (_context.Employee?.Any(e => e.EmployeeId == id)).GetValueOrDefault();
        }
    }

}
