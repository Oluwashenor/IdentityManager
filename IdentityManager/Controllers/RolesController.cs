using IdentityManager.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityManager.Controllers
{

    public class RolesController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RolesController(ApplicationDbContext db, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _userManager = userManager;
            _roleManager = roleManager;
        }
        public IActionResult Index()
        {
            var roles = _db.Roles.ToList();
            return View(roles);
        }

        [HttpGet]
        public IActionResult Upsert(string id)
        {
            if (String.IsNullOrEmpty(id))
            {
                return View();
            }
            else{
                //
                var objFromDb = _db.Roles.FirstOrDefault(u => u.Id == id);
                return View(objFromDb);
            }
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upsert(IdentityRole roleObj)
        {
         if(await _roleManager.RoleExistsAsync(roleObj.Name))
            {
                //Error
                TempData[SD.Error] = "Role already exists";
                return RedirectToAction(nameof(Index));
            }
         if(string.IsNullOrEmpty(roleObj.Id))
            {
                //Create
                await _roleManager.CreateAsync(new IdentityRole() { Name = roleObj.Name });
                TempData[SD.Success] = "Role Created Successfully";
            }
            else
            {
                
                //Update
                var roleInDb = _db.Roles.FirstOrDefault(r => r.Id == roleObj.Id);
                if(roleInDb == null)
                {
                    TempData[SD.Error] = "Role not found";
                    return RedirectToAction(nameof(Index));
                }
                roleInDb.Name = roleObj.Name;
                roleInDb.NormalizedName = roleObj.Name.ToUpper();
                var result = await _roleManager.UpdateAsync(roleInDb);
                TempData[SD.Success] = "Role updated Successfully";

            }
            return RedirectToAction(nameof(Index));
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string id)
        {
            var roleInDb = _db.Roles.FirstOrDefault(r => r.Id == id);
            var userRolesForThisRole = _db.UserRoles.Where(u => u.RoleId == id).Count();
            if(userRolesForThisRole > 0)
            {
                TempData[SD.Error] = "Cannot Delete Role, There are users allocated to it.";
                return RedirectToAction(nameof(Index));
            } 
            await _roleManager.DeleteAsync(roleInDb);
            TempData[SD.Success] = "Role deleted successfully";
            return RedirectToAction(nameof(Index));
        }
    }
}
