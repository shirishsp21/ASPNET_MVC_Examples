using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace JwtTokenAuthenticationWebApi.Auth
{
    public class AuthenticationHelper
    {
        private byte[] CreateSymmetricKey()
        {
            string secret = "3YExgUsPfeQTsfVC09Yo5IrwYZYuKOCfvAVfETh6TCQsM8nZHx7WEjk8oDRq0LCt0BcubhbFCtCMI24uMbaEik2Uf9QJGZ9E73wuFNnmV9cjyT7KElhyYvfL";
            return Encoding.UTF8.GetBytes(secret);
        }

        /*
        JWT token has following 3 components:
        -----------------------------------------------------
        1. Header
        {
            "typ": "JWT",
            "alg": "HS256"
        }
        In this method the algorithm used is SecurityAlgorithms.HmacSha256Signature
        -----------------------------------------------------
        2. Payload
        In this method we are putting 2 claims (ie username and userid) in payload.
        -----------------------------------------------------
        3. Signature
        In this method SigningCredentials is the signature.
        -----------------------------------------------------

        IMPORTANT:
        i)  Data inside a JWT is encoded and signed, not encrypted. Signing verifies authenticity of source of data.
        ii) JWT does NOT guarantee security for sensitive data. The secret we used during signing provider layer of security in our case.
        */
        public String GenerateJwtToken(String userName, String userId)
        {
            // payload.
            var claimsIdentity = new ClaimsIdentity(new List<Claim>()
            {
                new Claim(ClaimTypes.Name, userName),
                new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            }, "Custom");

            // header and signature.
            var tokenDescriptor = new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
            {
                Audience = "http://www.example.com",
                Subject = claimsIdentity,
                Issuer = "self",
                Expires = DateTime.UtcNow.AddDays(30),
                SigningCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                    new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(CreateSymmetricKey()), //symmetric key
                    System.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256Signature,
                    System.IdentityModel.Tokens.SecurityAlgorithms.Sha256Digest)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var plainToken = tokenHandler.CreateToken(tokenDescriptor);
            var signedAndEncodedToken = tokenHandler.WriteToken(plainToken);

            return signedAndEncodedToken;
        }

        public JwtSecurityToken ValidateJwtToken(string authToken)
        {
            // here we verify header and signature.
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudiences = new string[] { "http://www.example.com" },
                ValidIssuers = new string[] { "self" },
                IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(CreateSymmetricKey()), //symmetric key
            };
            var tokenHandler = new JwtSecurityTokenHandler();

            Microsoft.IdentityModel.Tokens.SecurityToken validatedToken;
            try
            {
                tokenHandler.ValidateToken(authToken, tokenValidationParameters, out validatedToken);
            }
            catch (Exception)
            {
                return null;
            }

            return validatedToken as JwtSecurityToken;
        }

        public JWTAuthenticationIdentity FetchUserIdentity(JwtSecurityToken jwtToken)
        {
            String userName = jwtToken.Claims.FirstOrDefault(c => c.Type == "unique_name").Value;
            String userId = jwtToken.Claims.FirstOrDefault(c => c.Type == "nameid").Value;
            return new JWTAuthenticationIdentity(userName) { UserId = userId, UserName = userName };
        }
    }
}