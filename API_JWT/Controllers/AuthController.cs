using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace API_JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private static User _user = new User();

        private IConfiguration _configuration;
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
       
        [HttpPost("Register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            _user.UserName = request.UserName;
            _user.PaswoordHash = passwordHash;
            _user.PasswordSalt = passwordSalt;

            return Ok(_user);
        }
        [HttpPost("Verify")]
        public async Task<ActionResult<string>> Verify(UserDto request)
        {
            if(_user.UserName != request.UserName || !VerifyPasswordHas(request.Password, _user.PaswoordHash, _user.PasswordSalt))
            {
                return BadRequest("Wrong user name or password");
            }
            else
            {

                return Ok(CreateToken(_user));
            }
        }

        private string CreateToken(User  user) 
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim (ClaimTypes.Name , user.UserName )
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSetting:Token").Value));
            var signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var token = new JwtSecurityToken(
                claims: claims,
                expires : DateTime.Now.AddDays(1),
                signingCredentials : signingCredentials
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private void CreatePasswordHash(string password,out byte[] passwordHash,out byte[] passwordSalt) 
        { 
            using(var hmac =new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHas(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512(passwordSalt)) 
            {
                var reGenaratePasHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return reGenaratePasHash.SequenceEqual(passwordHash);
            }
        }
    }
}
