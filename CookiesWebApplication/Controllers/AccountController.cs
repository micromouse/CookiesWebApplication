using CookiesWebApplication.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace CookiesWebApplication.Controllers {
    /// <summary>
    /// Account控制器
    /// </summary>
    [AllowAnonymous]
    public class AccountController : Controller {
        private readonly IMemoryCache _memoryCache;

        /// <summary>
        /// 初始化Account控制器
        /// </summary>
        /// <param name="memoryCache"><see cref="IMemoryCache"/></param>
        public AccountController(IMemoryCache memoryCache) {
            _memoryCache = memoryCache;
        }

        /// <summary>
        /// 登录
        /// </summary>
        /// <param name="returnUrl">返回Url</param>
        /// <returns>登录视图</returns>
        [HttpGet]
        public IActionResult Login(string returnUrl) {
            var model = new LoginViewModel {
                ReturnUrl = returnUrl
            };
            return View(model);
        }

        /// <summary>
        /// 登录
        /// </summary>
        /// <param name="model">登录视图模型</param>
        /// <returns>结果</returns>
        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model) {
            if (ModelState.IsValid) {
                if (model.Username == "admin" &&
                    model.Password == "111111") {
                    var claims = new[] {
                        new Claim(ClaimTypes.Name, model.Username),
                        new Claim(JwtRegisteredClaimNames.Sub, "112")
                    };
                    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var user = new ClaimsPrincipal(claimsIdentity);
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, user);
                    return Redirect(model.ReturnUrl);
                } else {
                    ModelState.AddModelError(string.Empty, "用户名或密码错误");
                }
            }

            //无效模型或用户名密码不匹配,重新显示登陆页面
            model = new LoginViewModel {
                ReturnUrl = model.ReturnUrl
            };
            return View(model);
        }

        /// <summary>
        /// 修改登录信息
        /// </summary>
        /// <returns>重定向到首页</returns>
        [HttpPost]
        public IActionResult ModifyLoginInfo() {
            var userId = HttpContext.User
                .Claims
                .FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Sub)?
                .Value;
            if (userId != null) {
                _memoryCache.Set($"revoke-{userId}", userId);
            }

            return RedirectToAction(nameof(HomeController.Index), "Home");
        }
    }
}
