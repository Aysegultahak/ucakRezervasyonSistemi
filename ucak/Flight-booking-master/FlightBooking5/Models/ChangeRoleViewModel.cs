using Microsoft.AspNetCore.Identity;

namespace FlightBooking5.Models
{
   
        public class ChangeRoleViewModel
        {
            public string UserId { get; set; }
            public string UserName { get; set; }
            public String CurrentRoles { get; set; }
            public List<IdentityRole> AllRoles { get; set; }
        }
    
}
