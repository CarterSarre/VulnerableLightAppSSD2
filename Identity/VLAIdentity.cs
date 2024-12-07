using System.Data;
using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;


namespace VulnerableWebApplication.VLAIdentity
{
    public class VLAIdentity
    {
        private static string Secret;

        public static void SetSecret(string secret)
        {
            Secret = secret;
        }

        private static string LogFile;

        public static void SetLogFile(string logFile)
        {
            LogFile = logFile;
        }


        public static async Task<object> VulnerableQuery(string User, string Passwd)
        {
            // Log the login attempt without including the password
            VLAController.VLAController.VulnerableLogs("Login attempt for: " + User, LogFile);

            // Retrieve user data (mocked in this example, replace with actual DB retrieval)
            var DataSet = VLAModel.Data.GetDataSet();

            // Find the user row (assuming you have a method to retrieve it, e.g., from a database)
            var userRow = DataSet.Tables[0].AsEnumerable()
                .FirstOrDefault(row => row.Field<string>("User") == User);

            if (userRow == null)
            {
                // User not found
                return Results.Unauthorized();
            }

            // Get the stored hashed password from the database
            string storedHashedPassword = userRow.Field<string>("Passwd");

            // Verify the password using bcrypt (assumes bcrypt is used to hash the password)
            bool isPasswordCorrect = BCrypt.Net.BCrypt.Verify(Passwd, storedHashedPassword);

            if (isPasswordCorrect)
            {
                // Check if user is an admin
                var isAdmin = userRow.Field<int>("IsAdmin") == 1;

                // Generate JWT token (assuming VulnerableGenerateToken is implemented elsewhere)
                var token = VulnerableGenerateToken(User, isAdmin);

                // Return the JWT token
                return Results.Ok(new { Token = token });
            }

            // If authentication fails, return unauthorized
            return Results.Unauthorized();
        }


        public static string VulnerableGenerateToken(string User, bool IsAdmin)
        {
            if (string.IsNullOrEmpty(User))
            {
                throw new ArgumentNullException(nameof(User), "Username cannot be null or empty.");
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(Environment.GetEnvironmentVariable("JWTSECRET"));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
            new Claim(ClaimTypes.Name, User),
            new Claim(ClaimTypes.Role, IsAdmin ? "Admin" : "User")
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }


        public static bool VulnerableValidateToken(string Token, string Secret)
        {
            /*
            Vérifie la validité du token JWT passé en paramètre
            */
            var TokenHandler = new JwtSecurityTokenHandler();
            var Key = Encoding.ASCII.GetBytes(Secret);
            bool Result = true;
            Token = Token.Substring("Bearer ".Length);

            try
            {
                var JwtSecurityToken = TokenHandler.ReadJwtToken(Token);
                if (JwtSecurityToken.Header.Alg == "HS256" && JwtSecurityToken.Header.Typ == "JWT")
                {
                    TokenHandler.ValidateToken(Token, new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Key),
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ValidateLifetime = true,
                    }, out SecurityToken validatedToken);

                    var JwtToken = (JwtSecurityToken)validatedToken;
                }
            }
            catch(Exception e) { Result = false; }

            return Result;
        }

        public static bool VulnerableAdminValidateToken(string Token, string Secret)
        {
            /*
            Vérifie la validité du token ADMIN passé en paramètre
            */
            var TokenHandler = new JwtSecurityTokenHandler();
            var Key = Encoding.ASCII.GetBytes(Secret);
            bool Result = false;
            Token = Token.Substring("Bearer ".Length);

            try
            {
                var JwtSecurityToken = TokenHandler.ReadJwtToken(Token);
                if (JwtSecurityToken.Header.Alg == "HS256" || JwtSecurityToken.Header.Typ == "JWT")
                {
                    TokenHandler.ValidateToken(Token, new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Key),
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ValidateLifetime = true,
                    }, out SecurityToken validatedToken);

                    var JwtToken = (JwtSecurityToken)validatedToken;
                    var claims = JwtToken.Claims;

                    var isAdminClaim = claims.FirstOrDefault(c => c.Type == "IsAdmin");
                    if (isAdminClaim.Value.Contains("True")) Result = true;
                }
            }
            catch (Exception e) { Result = false; }

            return Result;
        }


    }
}
