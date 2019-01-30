using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;

namespace ConsoleApp2
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            const string accessToken = "<your JWT>";
            
            var validatedToken = ValidateToken(accessToken);

            if (validatedToken == null)
            {
                Console.WriteLine("Invalid token");
            }
            else
            {
                Console.WriteLine("Token is valid!");
            }
        }

        private static JwtSecurityToken ValidateToken(string token)
        {
            const string issuer = "PingAccessAuthToken";

            if (string.IsNullOrEmpty(token)) throw new ArgumentNullException(nameof(token));
            if (string.IsNullOrEmpty(issuer)) throw new ArgumentNullException(nameof(issuer));
            
            var signingKeys = new SecurityKey[]
            {
                new JsonWebKey("{\"kty\":\"EC\",\"kid\":\"7\",\"use\":\"sig\",\"alg\":\"ES256\",\"x\":\"<your x here>\",\"y\":\"<your y here>\",\"crv\":\"P-256\"}"),
                new JsonWebKey("{\"kty\":\"EC\",\"kid\":\"4\",\"use\":\"sig\",\"alg\":\"ES256\",\"x\":\"<your x here>\",\"y\":\"<your y here>\",\"crv\":\"P-256\"}"),
                new JsonWebKey("{\"kty\":\"EC\",\"kid\":\"1\",\"use\":\"sig\",\"alg\":\"ES256\",\"x\":\"<your x here>\",\"y\":\"<your y here>\",\"crv\":\"P-256\"}")
            };

            var validationParameters = new TokenValidationParameters
            {
                ValidateAudience = false, //Had to set this to false. Not sure if you're interested in this
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,
                ValidateLifetime = true,
                // Allow for some drift in server time
                // (a lower value is better; we recommend two minutes or less)
                ClockSkew = TimeSpan.FromMinutes(2),
                // See additional validation for aud below
            };

            try
            {
                var principal = new JwtSecurityTokenHandler()
                    .ValidateToken(token, validationParameters, out var rawValidatedToken);

                return (JwtSecurityToken)rawValidatedToken;
            }
            catch (SecurityTokenValidationException ex)
            {
                return null;
            }
        }
    }
}
