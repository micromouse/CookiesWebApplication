using CookiesWebApplication.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Claims;

namespace CookiesWebApplication.Controllers {
    [Authorize]
    public class HomeController : Controller {
        private readonly ILogger<HomeController> _logger;
        private readonly IHttpContextAccessor _accessor;

        public HomeController(ILogger<HomeController> logger,
            IHttpContextAccessor accessor) {
            _logger = logger;
            _accessor = accessor;
        }

        public IActionResult Index() {
            _logger.LogInformation("当前登录用户[{CurrentUser}]正在访问Home.Index", this.GetLoginUser());
            return View();
        }

        public IActionResult Privacy() {
            _logger.LogInformation("当前登录用户[{CurrentUser}]正在访问Home.Privacy", this.GetLoginUser());
            ViewData.Add("UserName", this.GetLoginUser());
            return View();
        }

        /// <summary>
        /// 登出
        /// </summary>
        /// <returns>重定向到首页</returns>
        [HttpPost]
        public async Task<IActionResult> LogOut() {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Redirect("/");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error() {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private string GetLoginUser() {
            var name = "";
            if (_accessor.HttpContext?.User?.Identity != null) {
                var identity = (ClaimsIdentity)_accessor.HttpContext.User.Identity;
                name = identity.Claims.Single(x => x.Type == ClaimTypes.Name).Value;
            }

            return name;
        }
    }
}