using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using TokenAuthenticationNetCore.Data;
using TokenAuthenticationNetCore.Data.Models;
using TokenAuthenticationNetCore.Extensions;
using TokenAuthenticationNetCore.Models;
using TokenAuthenticationNetCore.Services;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace TokenAuthenticationNetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;      
        private readonly IConfiguration _configuration;
        private readonly ApplicationIdentityDbContext _context;
        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration configuration,ApplicationIdentityDbContext applicationIdentityDbContext)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _context = applicationIdentityDbContext;
        }

        [AllowAnonymous]
        [HttpPost("Register")]
        public async Task<IActionResult> RegisterUserAsync([FromBody] RegisterUserModel RegisterUserModelDTO)
        {
            JObject responseObject = new JObject();
            try
            {
                if (RegisterUserModelDTO == null)
                {
                    responseObject.Add("message", JToken.FromObject("Register request body cannot be null!"));
                    return UtilityExtensions.ReturnResponse(responseObject, HttpStatusCode.BadRequest);
                }

                if (!ModelState.IsValid)
                {
                    string modelErrorMessage = string.Join(" | ", ModelState.Values
                                                     .SelectMany(v => v.Errors)
                                                     .Select(e => e.ErrorMessage));

                    responseObject.Add("message", JToken.FromObject(modelErrorMessage));
                    return UtilityExtensions.ReturnResponse(responseObject, HttpStatusCode.BadRequest);
                }

                ApplicationUser newUser = new ApplicationUser
                {
                    UserName = RegisterUserModelDTO.UserName,
                    Email = RegisterUserModelDTO.Email,
                    FirstName = RegisterUserModelDTO.FirstName,
                    LastName = RegisterUserModelDTO.LastName,
                    Age = RegisterUserModelDTO.Age
                };

                //Set password options
                _userManager.Options.Password = new PasswordOptions
                {
                    RequireDigit = true,
                    RequiredLength = 8,
                    RequireNonAlphanumeric = false,
                    RequireUppercase = false,
                    RequireLowercase = true,
                    RequiredUniqueChars = 6
                };

                _userManager.Options.User.RequireUniqueEmail = true;

                IdentityResult result = await _userManager.CreateAsync(newUser, RegisterUserModelDTO.Password);

                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(newUser, false);
                    
                    await _userManager.AddToRoleAsync(newUser,"User");
                    string jwtSecurityToken = await GenerateJwtToken(newUser);
                    responseObject.Add("access_token", JToken.FromObject(jwtSecurityToken));
                    responseObject.Add("expires", JToken.FromObject(30));
                    responseObject.Add("email", JToken.FromObject(newUser.Email));
                    bool emailResult = new EmailHandling().SendVerificationEmail(newUser.Email,jwtSecurityToken).GetAwaiter().GetResult();
                    VerificationEmailModel verificationEmailModel = new VerificationEmailModel
                    {
                        RegisterId = Guid.NewGuid(),
                        Email = newUser.Email,
                        Token = jwtSecurityToken
                    };
                    await _context.Registrations.AddAsync(verificationEmailModel);
                    await _context.SaveChangesAsync();

                    return UtilityExtensions.ReturnResponse(responseObject, HttpStatusCode.Created);
                }
                else
                {
                    string modelCreationErrors = string.Join(string.Empty, result.Errors.SelectMany(x => x.Description));

                    responseObject.Add("message", JToken.FromObject($"User creation failed because of:\n{modelCreationErrors}"));
                    return UtilityExtensions.ReturnResponse(responseObject, HttpStatusCode.BadRequest);
                }
            }
            catch (Exception ex)
            {
                responseObject.Add("message", JToken.FromObject(ex.Message));
                return UtilityExtensions.ReturnResponse(responseObject, HttpStatusCode.InternalServerError);
            }
        }

        [AllowAnonymous]
        [HttpPost("Login")]
        public async Task<IActionResult> LoginUserAsync([FromBody] LoginModel LoginModelDTO)
        {
            JObject responseObject = new JObject();
            try
            {
                if (LoginModelDTO == null)
                {
                    responseObject.Add("message", JToken.FromObject("Login request body cannot be null!"));
                    return UtilityExtensions.ReturnResponse(responseObject, HttpStatusCode.BadRequest);
                }

                if(!ModelState.IsValid)
                {
                    string modelErrorMessage = string.Join(" | ", ModelState.Values
                                                    .SelectMany(v => v.Errors)
                                                    .Select(e => e.ErrorMessage));

                    responseObject.Add("message", JToken.FromObject(modelErrorMessage));
                    return UtilityExtensions.ReturnResponse(responseObject, HttpStatusCode.BadRequest);
                }

                SignInResult signInResult = await _signInManager.PasswordSignInAsync
                    (userName: LoginModelDTO.UserName, 
                     password: LoginModelDTO.Password, 
                     isPersistent: true, 
                     lockoutOnFailure: false);

                if (signInResult.Succeeded)
                {
                    ApplicationUser currentlyLoggedinUser = _userManager.Users.SingleOrDefault(x => x.UserName == LoginModelDTO.UserName);
                    IEnumerable<string> role = await _userManager.GetRolesAsync(currentlyLoggedinUser);
                    if(role.Count()>0)
                    {
                        responseObject.Add("role", JToken.FromObject(role.ElementAt(0)));
                    }
                    else
                    {
                        responseObject.Add("message", JToken.FromObject("User is unauthorized to login!!!"));
                        return UtilityExtensions.ReturnResponse(responseObject, HttpStatusCode.Unauthorized);
                    }
                    if(currentlyLoggedinUser == null)
                    {
                        responseObject.Add("message", JToken.FromObject("User with credentials not found"));
                        return UtilityExtensions.ReturnResponse(responseObject, HttpStatusCode.NotFound);
                    }
                    
                    string jwtSecurityToken = await GenerateJwtToken(currentlyLoggedinUser);
                    responseObject.Add("access_token", JToken.FromObject(jwtSecurityToken));
                    responseObject.Add("expires", JToken.FromObject(30));
                    responseObject.Add("email", JToken.FromObject(currentlyLoggedinUser.Email));
                    
                    return UtilityExtensions.ReturnResponse(responseObject, HttpStatusCode.OK);
                }
                else
                {
                    responseObject.Add("message", JToken.FromObject("User is unauthorized to login!!!"));
                    return UtilityExtensions.ReturnResponse(responseObject, HttpStatusCode.Unauthorized);
                }
            }
            catch (Exception ex)
            {
                responseObject.Add("message", JToken.FromObject(ex.Message));
                return UtilityExtensions.ReturnResponse(responseObject, HttpStatusCode.InternalServerError);
            }
        }
        //public async Task<IActionResult> UpdateUser([FromBody] RegisterUserModel EditedRegisterdUser)
        //{


        //}
        
        [HttpPost("VerifyEmail")]
        public async Task<IActionResult> VerifyEmail([FromBody] VerificationEmailModel VerificationEmailData)
        {
            JObject responseObject = new JObject();
            VerificationEmailModel model = _context.Registrations.Where(x => x.Token == VerificationEmailData.Token && x.Email == VerificationEmailData.Email).FirstOrDefault();
            try
            {
                if (model == null)
                {
                    responseObject.Add("message", JToken.FromObject("false"));
                    return UtilityExtensions.ReturnResponse(responseObject, HttpStatusCode.InternalServerError);
                }
                responseObject.Add("message", JToken.FromObject("true"));
                return UtilityExtensions.ReturnResponse(responseObject, HttpStatusCode.OK);
            }
            catch(Exception ex)
            {
                responseObject.Add("message", JToken.FromObject("false"));
                return UtilityExtensions.ReturnResponse(responseObject, HttpStatusCode.InternalServerError);
            }
        }


        [Authorize(Roles = "Admin")]
        [HttpPost("AddAdmin")]
        public IActionResult AddAdmin([FromBody] JObject AddAdminRequestBody)
        {
            JObject resposneObject = new JObject();

            resposneObject.Add("message", JToken.FromObject("Admin Success"));
            return UtilityExtensions.ReturnResponse(resposneObject,HttpStatusCode.OK);
        }
        [Authorize(Roles = "User")]
        [HttpPost("UserHome")]
        public IActionResult UserHome([FromBody] JObject AddAdminRequestBody)
        {
            JObject resposneObject = new JObject();

            resposneObject.Add("message", JToken.FromObject("User Success"));
            return UtilityExtensions.ReturnResponse(resposneObject, HttpStatusCode.OK);
        }
        #region Helper methods
        private async Task<string> GenerateJwtToken(ApplicationUser user)
        {
            IEnumerable<string> roleList =await _userManager.GetRolesAsync(user);

            List<Claim> claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Role,roleList.ElementAt(0)),
                new Claim(JwtRegisteredClaimNames.Iat,DateTime.UtcNow.Second.ToString())
            };

            //Generate your own secret key using the following lines:
            //HMACSHA256 hmac = new HMACSHA256();
            //string secretKey = Convert.ToBase64String(hmac.Key);

            SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtKey"]));
            SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            DateTime expires = DateTime.UtcNow.AddMinutes(30);

            JwtSecurityToken token = new JwtSecurityToken(
                _configuration["JwtIssuer"],
                _configuration["JwtIssuer"],
                claims,
                expires: expires,
                signingCredentials: credentials
            );

            string jwtSecurityToken = new JwtSecurityTokenHandler().WriteToken(token);
            return jwtSecurityToken;
        }


        private async Task<List<Claim>> GetValidClaims(ApplicationUser user)
        {
            IdentityOptions _options = new IdentityOptions();
            List<Claim> claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id)
            };

            //var userClaims = await _userManager.GetClaimsAsync(user);
            //var userRoles = await _userManager.GetRolesAsync(user);
            //claims.AddRange(userClaims);
            //foreach (var userRole in userRoles)
            //{
            //    claims.Add(new Claim(ClaimTypes.Role, userRole));
            //    var role = await _roleManager.FindByNameAsync(userRole);
            //    if (role != null)
            //    {
            //        var roleClaims = await _roleManager.GetClaimsAsync(role);
            //        foreach (Claim roleClaim in roleClaims)
            //        {
            //            claims.Add(roleClaim);
            //        }
            //    }
            //}
            return claims;
        }
        #endregion
    }
}