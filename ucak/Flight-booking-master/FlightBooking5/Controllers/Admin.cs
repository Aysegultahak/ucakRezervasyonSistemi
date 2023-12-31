using FlightBooking5.Data;
using FlightBooking5.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;


namespace FlightBooking5.Controllers
{
    public class Admin : Controller
    {
        private readonly FlightBooking5Context _context;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<IdentityUser> _userManager;

        public Admin(FlightBooking5Context context, RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager)
        {
            _context = context;
            _roleManager = roleManager;
            _userManager = userManager;
        }
        [Authorize(Roles="Admin Manager")]
        [HttpGet]
        public IActionResult ChangeRole(string userName)
        {

            // Lấy thông tin người dùng dựa trên userId
            var user = _userManager.FindByNameAsync(userName).Result;

            if (user == null)
            {
                // Xử lý khi không tìm thấy người dùng
                return NotFound();
            }

            // Lấy danh sách vai trò hiện tại của người dùng
            var currentRoles = _userManager.GetRolesAsync(user).Result;

            // Lấy danh sách tất cả vai trò có sẵn
            var allRoles = _roleManager.Roles.ToList();

            // Tạo view model để truyền dữ liệu cho view
            var viewModel = new ChangeRoleViewModel
            {
                UserId = user.Id,
                UserName = user.UserName,
                CurrentRoles = currentRoles.ToString(),
                AllRoles = allRoles
            };

            return View("ChangeRole", viewModel);
        }
        [Authorize(Roles = "Admin Manager")]
        [HttpPost]
        public IActionResult UpdateRole(string userId, string roleId)
        {
            // Lấy thông tin người dùng dựa trên userId
            var user = _userManager.FindByIdAsync(userId).Result;

            if (user == null)
            {
                // Xử lý khi không tìm thấy người dùng
                return NotFound();
            }

            // Lấy vai trò mới dựa trên roleId
            var role = _roleManager.FindByIdAsync(roleId).Result;

            if (role == null)
            {
                // Xử lý khi không tìm thấy vai trò
                return NotFound();
            }

            // Xóa tất cả các vai trò hiện tại của người dùng
            var currentRoles = _userManager.GetRolesAsync(user).Result;
            _userManager.RemoveFromRolesAsync(user, currentRoles).Wait();

            // Thêm vai trò mới cho người dùng
            _userManager.AddToRoleAsync(user, role.Name).Wait();

            // Điều hướng đến trang hiển thị thông báo thành công hoặc trang khác tùy ý

            return View("SuccessChangeRole");

        }
        [Authorize(Roles = "Admin Manager")]
        public IActionResult InputUser()
        {
            return View();
        }
        [Authorize(Roles = "Admin Manager, Marketing,Employee")]
        public IActionResult Index()
        {
            return View("Admin");
        }
        public async Task<IActionResult> AddFlight()
        {
            return _context.Flight != null ?
                       View(await _context.Flight.ToListAsync()) :
                       Problem("Entity set 'FlightBooking5Context.Flight'  is null.");
        }
        [Authorize(Roles = "Admin Manager")]
        public async Task<IActionResult> AddRole()
        {
            var roles = _roleManager.Roles;

            return View("AddRole", roles);
        }
        [Authorize(Roles = "Admin Manager")]
        public async Task<IActionResult> PaymentDetails()
        {
            List<PaymentDetails> paymentDetails = await _context.PaymentDetails.ToListAsync();
            return View("PaymentDetails", paymentDetails);
        }
        [Authorize(Roles = "Admin Manager")]
        public async Task<IActionResult> EmployeeAssignment()
        {
            return _context.Employee != null ?
                         View(await _context.Employee.ToListAsync()) :
                         Problem("Entity set 'FlightBooking5Context.Employee'  is null.");
        }
        [Authorize(Roles = "Employee")]
        public async Task<IActionResult> EmployeeSchedule()


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
        [Authorize(Roles = "Admin Manager, Marketing")]
        public async Task<IActionResult> Ads()
        {
            return _context.ImageAd != null ?
                         View("Advertisement",await _context.ImageAd.ToListAsync()) :
                         Problem("Entity set 'FlightBooking5Context.ImageAd'  is null.");


        }
    }
}
