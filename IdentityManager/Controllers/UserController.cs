using IdentityManager.Data;
using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityManager.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _userManager;

        public UserController(ApplicationDbContext db, UserManager<IdentityUser> userManager)
        {
            _db = db;
            _userManager = userManager;
        }

        public IActionResult Index()
        {
            var userList = _db.ApplicationUser.ToList();
            var userRole = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            foreach(var user in userList)
            {
                var role = userRole.FirstOrDefault(u=>u.UserId == user.Id);
                if(role == null)
                {
                    user.Role = "None";
                }
                else
                {
                    user.Role = roles.FirstOrDefault(r => r.Id == role.RoleId).Name;
                }
            }
            return View(userList);
        }


        public IActionResult Edit(string userId)
        {
            var userFromDb = _db.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if(userFromDb == null)
            {
                return NotFound();
            }
            var userRole = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();
            var role = userRole.FirstOrDefault(u => u.UserId == userFromDb.Id);
            if (role != null)
            {
                userFromDb.RoleId = roles.FirstOrDefault(u => u.Id == role.RoleId).Id;
            }
            userFromDb.RoleList = _db.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            {
                Text = u.Name,
                Value = u.Id
            });
            return View(userFromDb);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(ApplicationUser user)
        {
            if (ModelState.IsValid)
            {
                var userFromDb = _db.ApplicationUser.FirstOrDefault(u => u.Id == user.Id);
                if (userFromDb == null)
                {
                    return NotFound();
                }
                var userRole = _db.UserRoles.FirstOrDefault(u => u.UserId == user.Id);
                if (userRole != null)
                {
                    var previousRole = _db.Roles.Where(u => u.Id == userRole.RoleId).Select(e => e.Name).FirstOrDefault();
                    // Remove Old Role
                    await _userManager.RemoveFromRoleAsync(userFromDb, previousRole);

                }
                // Add new Role 
                await _userManager.AddToRoleAsync(userFromDb, _db.Roles.FirstOrDefault(u => u.Id == user.RoleId).Name);
                userFromDb.Name = user.Name;
                _db.SaveChanges();
                TempData[SD.Success] = "User has been Edited Successfully";
                return RedirectToAction(nameof(Index));
            }
            else
            {
                user.RoleList = _db.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
                {
                    Text = u.Name,
                    Value = u.Id
                });
                return View(user);
            }
        }

        [HttpPost]
        public IActionResult LockUnlock(string userId)
        {
            var userFromDb = _db.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if(userFromDb == null)
            {
                return NotFound();
            }
            if(userFromDb.LockoutEnd!= null && userFromDb.LockoutEnd > DateTime.Now)
            {
                // user is locked and will remain locked until locked out time end 
                // Clicking on this action will unlock them 
                userFromDb.LockoutEnd = DateTime.Now;
                TempData[SD.Success] = "User has been Unlocked Successfully";
            }
            else
            {
                //user is not locked and e want to lock the user
                userFromDb.LockoutEnd = DateTime.Now.AddYears(1000);
                TempData[SD.Success] = "User has been Locked Successfully";
            }
            _db.SaveChanges();
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        public IActionResult Delete(string userId)
        {
            var userFromDb = _db.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if (userFromDb == null)
            {
                return NotFound();
            }
            _db.ApplicationUser.Remove(userFromDb);
            _db.SaveChanges();
            TempData[SD.Success] = "User has been Deleted Successfully";
            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public async Task<IActionResult> ManageUserClaims(string userId)
        {
            IdentityUser user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }
            var existingUserClaims = await _userManager.GetClaimsAsync(user);
            var model = new UserClaimsViewModel()
            {
                UserId = userId
            };
            foreach(Claim claim in ClaimStore.claimsList)
            {
                UserClaim userClaim = new UserClaim
                {
                    ClaimType = claim.Type
                };
                if(existingUserClaims.Any(c=>c.Type== claim.Type))
                {
                    userClaim.IsSelected = true;
                }
                model.Claims.Add(userClaim);
            }

            return View(model);

        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageUserClaims(UserClaimsViewModel userClaimsViewModel)
        {
            IdentityUser user = await _userManager.FindByIdAsync(userClaimsViewModel.UserId);
            if (user == null)
            {
                return NotFound();
            }
            var claims = await _userManager.GetClaimsAsync(user);
            var result = await _userManager.RemoveClaimsAsync(user, claims);

            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error Removing Claims";
                return View(userClaimsViewModel);
            }
            result = await _userManager.AddClaimsAsync(user,
                userClaimsViewModel.Claims.Where(c=>c.IsSelected).Select(c=>new Claim(c.ClaimType,c.IsSelected.ToString())));
            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error adding Claims";
                return View(userClaimsViewModel);
            }
            TempData[SD.Success] = "Claims Updated Successfully";
            return RedirectToAction(nameof(Index));

        }

    }
}
