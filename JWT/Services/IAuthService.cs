using JWT.Models;

namespace JWT.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterModel register);
        Task<AuthModel> GetTokenAsync(TokenRequestModel model);
        Task<string> AddRoleAsync(AddRoleModel model);
    }
}
