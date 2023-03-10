using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Data.SqlClient;
using Microsoft.AspNetCore.Authorization;
using System.Text;
using System.Collections.Generic;
using JWT.Model;

namespace JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;

        }
           
        [HttpPost("register")]
        public async Task <ActionResult<User>> Register(UserDto request)
        {
            CreatePassword(request.password, out byte[] passwordHash, out byte[] passwordSalt);
            user.username = request.username;
            user.PasswordHarsh = passwordHash;
            user.PasswordSalt = passwordSalt;
            return Ok(user);
        }
        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if (user.username != request.username)
            {
                return BadRequest("User not found");
            }
            if (!VerifyPassword(request.password, user.PasswordHarsh, user.PasswordSalt))
            {
                return BadRequest("Wrong Password");
            }
            string token = CreateToken(user);

            // Store the token in the response
            HttpContext.Response.Headers.Add("Authorization", "Bearer " + token);

            return Ok(token);
        }

        [Authorize]
        [HttpGet("data")]
        public  async Task<ActionResult<string>> Get()
        {
            // Retrieve the authenticated user's username
            var username = User.FindFirst(ClaimTypes.Name)?.Value;

            // Use the username to retrieve the user's data from the database
            string connectionString = "Data Source=DESKTOP-28IF1RN;Initial Catalog=ItemRecords;Integrated Security=True;";
        List<ItemRecords> items = new List<ItemRecords>();
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            SqlCommand command = new SqlCommand("SELECT ItemCode, ItemName, BuyingPrice, SellingPrice, Terminus FROM Items", connection);
            connection.Open();
            SqlDataReader reader =  command.ExecuteReader();
            while (reader.Read())
            {
                    ItemRecords item = new ItemRecords
                    {
                        ItemCode = (int)reader.GetInt64(0),
                        ItemName = reader.GetString(1),
                        BuyingPrice = (double)reader.GetDecimal(2),
                        SellingPrice = (double)reader.GetDecimal(3),
                        Terminus = reader.GetString(5)
                };
                items.Add(item);
            }
            reader.Close();
        }

       return new OkObjectResult(items);




        }


        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {
               new Claim (ClaimTypes.Name, user.username)
            };
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSetting:Token").Value));
            var cred =  new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims : claims,
                expires : DateTime.Now.AddDays(1),
                signingCredentials : cred
                );
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
        private void CreatePassword(string password, out byte[] passwordHash, out byte[] passwordSalt) 
        {
            using (var hmac = new HMACSHA512()) 
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        
        }
        private bool VerifyPassword(string password,  byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }

    public class Token
    {
        public string Value { get; set; }
    }
}
