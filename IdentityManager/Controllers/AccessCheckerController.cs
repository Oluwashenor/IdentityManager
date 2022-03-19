using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityManager.Controllers
{
    [Authorize]
    public class AccessCheckerController : Controller
    {
        // Accessible by everyone
        [AllowAnonymous]
        public IActionResult AllAccess()
        {
            return View();
        }

        // accessile by logged in users 
        [Authorize]
        public IActionResult AuthorizedAccess()
        {
            return View();
        }

        [Authorize(Roles = "User")]
        // Accessible by users who have user role 
        public IActionResult UserAccess()
        {
            return View();
        }

        [Authorize(Roles = "User,Admin")]
        // Accessible by users who have user role 
        public IActionResult UserOrAdminAccess()
        {
            return View();
        }
        //Accessbile by users who have admin role
        public IActionResult AdminAccess()
        {
            return View();
        }

        // Accessible by admin users with a claim of create to be true 
        public IActionResult Admin_CreateAccess()
        {
            return View();
        }

        // Accessible by admin with claim of create edit and delete (AND not OR)
        public IActionResult Admin_Create_Edit_DeleteAccess()
        {
            return View();
        }
        // accessible by admin user with create, edit and delete (And NOT OR), OR if the user is superadmin
        public IActionResult Admin_Create_Edit_DeleteAccess_SuperAdmin()
        {
            return View();
        }
    }
}
