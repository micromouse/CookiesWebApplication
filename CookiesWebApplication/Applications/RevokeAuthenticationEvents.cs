using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Memory;
using System.IdentityModel.Tokens.Jwt;

namespace CookiesWebApplication.Applications {
    /// <summary>
    /// 撤销Cookie认证事件
    /// </summary>
    public class RevokeAuthenticationEvents : CookieAuthenticationEvents {
        private readonly IMemoryCache _cache;
        private readonly ILogger _logger;

        /// <summary>
        /// 初始化撤销Cookie认证事件
        /// </summary>
        /// <param name="cache"><see cref="IMemoryCache"/></param>
        /// <param name="logger">日志器</param>
        public RevokeAuthenticationEvents(IMemoryCache cache, 
            ILogger<RevokeAuthenticationEvents> logger) {
            _cache = cache;
            _logger = logger;
        }

        /// <summary>
        /// 验证凭据
        /// </summary>
        /// <param name="context">Cookie验证凭据上下文</param>
        /// <returns>任务</returns>
        public override async Task ValidatePrincipal(CookieValidatePrincipalContext context) {
            var userId = context.Principal?
                .Claims
                .FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?
                .Value;
            if (userId != null) {
                if (_cache.TryGetValue($"revoke-{userId}", out var revokeKeys)) {
                    _logger.LogDebug("Access has been revoked for: {UserId}.", userId);
                    context.RejectPrincipal();
                    _cache.Remove($"revoke-{userId}");
                    await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                }
            }
        }
    }
}
