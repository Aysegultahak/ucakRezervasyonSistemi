using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace FlightBooking5.Controllers
{
	public class AppRoleController : Controller
	{
		private readonly RoleManager<IdentityRole> _roleManager;
        public AppRoleController(RoleManager<IdentityRole> roleManager)
        {
			_roleManager = roleManager;

		}
        //list all roles
        [Authorize(Roles = "Admin Manager")]
        public IActionResult Index()
		{
			var roles = _roleManager.Roles;
			return View(roles);
		}
		[HttpGet]
        [Authorize(Roles = "Admin Manager")]
        public IActionResult Create()
		{
			
			return View();
		}
		[HttpPost]
		public async Task<IActionResult>  Create(IdentityRole model)
		{
			if(!_roleManager.RoleExistsAsync(model.Name).GetAwaiter().GetResult()) 
			{
				_roleManager.CreateAsync(new IdentityRole(model.Name)).GetAwaiter().GetResult();
			}
			return RedirectToAction("AddRole", "Admin");
		}
	}
}
