using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AuthAPI.Constants;
using AuthAPI.Models;
using AuthAPI.Models.BindingModels;
using AuthAPI.Models.ResourceModels;
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
        public object EntityConstans { get; private set; }

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
                        DisplayName = "Test User",
                        Email = "testuser@test.com",
                        Password = "ABCabc123!@#"
                    },
                    response = new
                    {
                        UserName = "TestUser",
                        DisplayName = "Test User",
                        Email = "testuser@test.com",
                        Password = "ABCabc123!@#"
                    },
                },
                adminregister = new
                {
                    type = "POST",
                    authorization = "Bearer",
                    route = "/api/auth/adminregister",
                    content_type = "JSON",
                    body = new
                    {
                        UserName = "TestUser",
                        DisplayName = "Test User",
                        Email = "testuser@test.com",
                        Role = "Admin",
                        Password = "ABCabc123!@#"
                    },
                    response = new
                    {
                        UserName = "TestUser",
                        DisplayName = "Test User",
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
                        thisuser = new UserResourceModel
                        {
                            UserName = "TestUser",
                            DisplayName ="Test User",
                            Email = "testuser@test.com",
                            Role = "User"
                        },
                        token = "BJG273GJDAS73GDAKJDSH.hgJG7hjvj7jhjgu7jhgj.GUTYGu6GV655Yd3gcH",
                        expiration = "30mins"

                    },
                },
                GuestLogin = new
                {
                    type = "POST",
                    route = "/api/auth/GuestLogin",
                    content_type = "JSON",
                    body = new
                    {
                        DisplayName = "test guest",
                    },
                    response = new
                    {
                        thisuser = new UserResourceModel
                        {
                            UserName = "717b38d7-fda7-4485-5109-08d767a61944",
                            DisplayName = "Test Guest",
                            Email = "test717b38d7-fda7-4485-5109-08d767a61944@guest.user",
                            Role = "Guest"
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
            var roles = await UserMgr.GetRolesAsync(user);
            var returnuser = new UserResourceModel
            {
                UserName = user.UserName,
                DisplayName =user.DisplayName,
                Role = roles.FirstOrDefault().ToString(),
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
                        var roles = await UserMgr.GetRolesAsync(user);

                        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JWTSettings.Secret));
                        var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                        var claims = new[]
                        {

                            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                            new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                            new Claim("Role",roles.FirstOrDefault()),

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
                            thisuser = new UserResourceModel { UserId = user.Id, UserName = user.UserName, DisplayName = user.DisplayName, Email = user.Email, Role = roles.FirstOrDefault() },
                            token = new JwtSecurityTokenHandler().WriteToken(token),
                            expiration = token.ValidTo
                        };
                        return Ok(results);

                    }
                    else
                    {
                        var err2 = new { status = "error", message = "Authentication Failed ! Check Email & Password" };
                        return BadRequest(err2);
                    }
                }

                var err = new { status = "error", message = "Could not find a user for given Email!" };
                return BadRequest(err);
            }

            return BadRequest();
        }








        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterBindingModel model)
        {
                try
                {

                    User user = await UserMgr.FindByEmailAsync(model.Email);
                    if (user == null)
                    {
                        user = new User
                        {
                            UserName = model.UserName,
                            DisplayName = model.DisplayName,
                            Email = model.Email,
                           
                        };

                        IdentityResult result = await UserMgr.CreateAsync(user, model.Password);
                        await UserMgr.AddToRoleAsync(user, EntityConstants.Role_RegisteredUser);
                        if (result.Succeeded)
                        {
                            return Created("", model);
                        }
                        else
                        {
                            var err = new { status = "error", message = "User registration " + result.ToString()};
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

        [HttpPost("GuestLogin")]
        public async Task<IActionResult> GuestLogin(GuestLoginBindingModel model)
        {
                try
                {
                    if (model.DisplayName != null)
                    {
                        var user = new User
                        {
                            UserName = Guid.NewGuid().ToString(),
                            DisplayName = model.DisplayName,
                            Email = model.DisplayName + "_" + Guid.NewGuid().ToString() + "@guest.user",


                        };

                        IdentityResult result = await UserMgr.CreateAsync(user, "GuestUser1s-"+Guid.NewGuid().ToString());
                        await UserMgr.AddToRoleAsync(user, EntityConstants.Role_GuestUser);
                        if (result.Succeeded)
                        {
                            
                            User guest_user = await UserMgr.FindByEmailAsync(user.Email);
                            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JWTSettings.Secret));
                            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                            var claims = new[]
                            {

                                new Claim(JwtRegisteredClaimNames.Sub, guest_user.Email),
                                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                                new Claim("Role",EntityConstants.Role_GuestUser),

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
                                thisuser = new UserResourceModel { UserId = guest_user.Id, UserName = guest_user.UserName, DisplayName = guest_user.DisplayName, Email = guest_user.Email, Role = EntityConstants.Role_GuestUser },
                                token = new JwtSecurityTokenHandler().WriteToken(token),
                                expiration = token.ValidTo
                            };
                            return Ok(results);
                    }
                        else
                        {
                            var err = new { status = "error", message = "Guest User Creation " + result.ToString() };
                            return BadRequest(err);
                        }

                    }
                    else
                    {
                        var err = new { status = "error", message = "DisplayName required!" };
                        return BadRequest(err);
                    }
                }
                catch (Exception ex)
                {
                    var err = new { status = "error", message = ex.Message };
                    return BadRequest(err);
                }

        }


        [HttpPost("AdminRegister")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        public async Task<IActionResult> AdminRegister(RegisterBindingModel model)
        {
            string usertype = User.Claims.First(c => c.Type == "Role").Value;
            if (usertype.Equals(EntityConstants.Role_SuperAdmin) || usertype.Equals(EntityConstants.Role_Admin))
            {

                try
                {

                    User user = await UserMgr.FindByEmailAsync(model.Email);
                    if (user == null)
                    {
                        user = new User
                        {
                            UserName = model.UserName,
                            DisplayName = model.DisplayName,
                            Email = model.Email,

                        };

                        IdentityResult result = await UserMgr.CreateAsync(user, model.Password);
                        await UserMgr.AddToRoleAsync(user, model.Role);
                        if (result.Succeeded)
                        {
                            return Created("", model);
                        }
                        else
                        {
                            var err = new { status = "error", message = "User registration " + result.ToString() };
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
                return Forbid();
            }

        }



    }
}