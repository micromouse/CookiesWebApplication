namespace CookiesWebApplication.Models {
    /// <summary>
    /// 登录视图模型
    /// </summary>
    public class LoginViewModel {
        /// <summary>
        /// 返回Url
        /// </summary>
        public string ReturnUrl { get; init; } = "/";
        /// <summary>
        /// 用户名
        /// </summary>
        public string? Username { get; init; }
        /// <summary>
        /// 密码
        /// </summary>
        public string? Password { get; init; }
    }
}
