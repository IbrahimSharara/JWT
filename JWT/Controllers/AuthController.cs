using JWT.Models;
using JWT.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JWT.Controllers
{
    //[Authorize(Roles ="user")]
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public IAuthService _Auth { get; }

        public AuthController(IAuthService auth)
        {
            _Auth = auth;
        }
        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync(RegisterModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result = await _Auth.RegisterAsync(model);
            if(! result.IsAUthenticated)
            {
                return BadRequest(result.Message);
            }
            // i can return result object directly or return which prop i want 

            //return Ok(result);
            return Ok(new AuthModel
            {
                Email = result.Email,
                Token = result.Token,
                UserName = result.UserName
            });
        }

        [HttpPost("token")]
        public async Task<IActionResult> GetTokenAsync([FromBody]TokenRequestModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result = await _Auth.GetTokenAsync(model);
            if (!result.IsAUthenticated)
            {
                return BadRequest(result.Message);
            }
            // i can return result object directly or return which prop i want 

            //return Ok(result);
            return Ok(new AuthModel
            {
                Email = result.Email,
                Token = result.Token,
                UserName = result.UserName
            });
        }

        [HttpPost("role")]
        public async Task<IActionResult> AddRoleAsync(AddRoleModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result = await _Auth.AddRoleAsync(model);
            if(! string.IsNullOrEmpty(result))
                return BadRequest(result);
            return Ok(model) ;
        }
    }
}
