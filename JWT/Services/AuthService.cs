using JWT.Helpers;
using JWT.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> manager;
        private readonly JWTClass _jwt;

        public AuthService(UserManager<ApplicationUser> manager , RoleManager<IdentityRole> role, IOptions<JWTClass> _jwt)
        {
            this.manager = manager;
            Role = role;
            this._jwt = _jwt.Value;
        }

        public RoleManager<IdentityRole> Role { get; }

        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            var user = await manager.FindByIdAsync(model.UserId);
            if (user == null | !await Role.RoleExistsAsync(model.Role))
                return "Invalide user ID or Role !";
            if (await manager.IsInRoleAsync(user ,model.Role))
                return "User Is already asigned to this role";
            var result = await manager.AddToRoleAsync(user, model.Role);
            return result.Succeeded ? string.Empty :  "Some Thing went wrong !";
        }

        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            var authModel = new AuthModel();
            var user = await manager.FindByEmailAsync(model.Email);
            if (user is null || !await manager.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "Email or Password is incorrect !";
                return authModel;
            }
            var jwtAuthToken = await CreateJwtToken(user);
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtAuthToken);
            authModel.IsAUthenticated = true;
            authModel.Email = user.Email;
            authModel.ExpiresOn = jwtAuthToken.ValidTo;
            authModel.UserName = user.UserName;
            var rolesList = await manager.GetRolesAsync(user);
            authModel.Roles = rolesList.ToList();
            return authModel;
        }

        public async Task<AuthModel> RegisterAsync(RegisterModel register)
        {
            #region check user signed up before
            if (await manager.FindByNameAsync(register.UserName) is not null)
                return new AuthModel { Message = "UserName is already used !" };
            if (await manager.FindByEmailAsync(register.Email) is not null)
                return new AuthModel { Message = "Email is already used !" };
            #endregion
            // create new usew from the inserted data
            var user = new ApplicationUser
            {
                Email = register.Email,
                FirstName = register.FirstName,
                LastName = register.LastName,
                UserName = register.UserName,
            };
            // create user at DB
            var result = await manager.CreateAsync(user, register.Password);
            // check if any error happened
            if (!result.Succeeded)
            {
                var errors = "";
                foreach (var item in result.Errors)
                {
                    errors += $"{item.Description}, ";
                }
                return new AuthModel { Message = errors };
            }
            // here user is add and assign user role to him by default
            await manager.AddToRoleAsync(user, "User");
            var jwtSecurityToken = await CreateJwtToken(user);
            return new AuthModel
            {
                Email = user.Email ,
                ExpiresOn = jwtSecurityToken.ValidTo ,
                IsAUthenticated = true ,
                Roles = new List<string> { "User"} ,
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                UserName = user.UserName
            };
        }

        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await manager.GetClaimsAsync(user);
            var roles = await manager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
    }
}
