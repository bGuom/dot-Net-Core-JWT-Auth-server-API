using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]


    public class AuthController : ControllerBase
    {

        private UserManager<User> UserMgr { get; }
        private SignInManager<User> SignInMgr { get; }

        private JWTSettings JWTSettings { get; }
        private readonly IdentityContext _context;

        public AuthController(UserManager<User> usermanager, SignInManager<User> signinmanager, IdentityContext logcontext, IOptions<JWTSettings> settings)
        {
            UserMgr = usermanager;
            SignInMgr = signinmanager;
            _context = logcontext;
            JWTSettings = settings.Value;
        }


        [HttpGet("index")]
        public IActionResult Index()
        {
            return Ok(new{
                status = "Auth Server started",
                register = new {
                    type = "POST",
                    route = "/api/auth/register",
                    content_type ="JSON",
                    body =new {
                        UserName = "TestUser",
                        Email = "testuser@test.com",
                        Password = "ABCabc123!@#"
                    },
                    response = new
                    {
                        UserName = "TestUser",
                        Email = "testuser@test.com",
                        Password = "ABCabc123!@#"
                    },
                },
                getToken = new
                {
                    type = "POST",
                    route = "/api/auth/GetToken",
                    content_type = "JSON",
                    body = new
                    {
                        Email = "testuser@test.com",
                        Password = "ABCabc123!@#"
                    },
                    response = new {
                        thisuser = new User
                        {
                            UserName = "TestUser",
                            Email = "testuser@test.com",
                        },
                        token = "BJG273GJDAS73GDAKJDSH.hgJG7hjvj7jhjgu7jhgj.GUTYGu6GV655Yd3gcH",
                        expiration = "30mins"

                    },
                },

            });
        }



        [HttpGet("info")]
        [Authorize(AuthenticationSchemes = JWTSettings.AuthScheme)]
        public async Task<IActionResult> getinfoAsync()
        {
            string email = User.Claims.First(c => c.Type == "Email").Value;
            User user = await UserMgr.FindByEmailAsync(email);
            var returnuser = new
            {
                Username = user.UserName,
                Email = user.Email,
            };
            return Ok(returnuser);
        }


                          



        [HttpPost("GetToken")]
        public async Task<IActionResult> GenerateToken([FromBody]AuthBindingModel model)
        {
            if (ModelState.IsValid)
            {

                User user = await UserMgr.FindByEmailAsync(model.Email);
                if (user != null)
                {
                    var signInResult = await SignInMgr.CheckPasswordSignInAsync(user, model.Password.ToString(), false);

                    if (signInResult.Succeeded)
                    {

                        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JWTSettings.Secret));
                        var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                        var claims = new[]
                        {

                            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                            new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                            new Claim("UserType",""),

                        };

                        var token = new JwtSecurityToken(

                            JWTSettings.Issuer,
                            JWTSettings.Audience,
                            claims,
                            expires: DateTime.UtcNow.AddMinutes(JWTSettings.ExpieryTimeInMins),
                            signingCredentials: cred

                            );

                        var results = new
                        {
                            thisuser = new { UserName = user.UserName, Email = user.Email },
                            token = new JwtSecurityTokenHandler().WriteToken(token),
                            expiration = token.ValidTo
                        };
                        return Ok(results);

                    }
                    else
                    {
                        var err2 = new { status = "error", message = "Authentication Failed ! Check UserName & Password" };
                        return BadRequest(err2);
                    }
                }

                var err = new { status = "error", message = "Could not find a user!" };
                return BadRequest(err);
            }

            return BadRequest();
        }








        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterBindingModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {

                    User user = await UserMgr.FindByEmailAsync(model.Email);
                    if (user == null)
                    {
                        user = new User
                        {
                            UserName = model.Username,
                            Email = model.Email,
                           
                        };

                        IdentityResult result = await UserMgr.CreateAsync(user, model.Password);
                        //await UserMgr.AddToRoleAsync(user, user.Type);
                        if (result.Succeeded)
                        {
                            return Created("", model);
                        }
                        else
                        {
                            var err = new { status = "error", message = "User registration failed! "};
                            return BadRequest(err);
                        }

                    }
                    else
                    {
                        //User Already exsist
                        var err = new { status = "error", message = "User already exsist!" };
                        return BadRequest(err);
                    }
                }
                catch (Exception ex)
                {
                    var err = new { status = "error", message = ex.Message };
                    return BadRequest(err);
                }
            }
            else
            {
                var err = new { status = "error", message = "Invalid details" };
                return BadRequest(err);
            }


        }

      

    }
}