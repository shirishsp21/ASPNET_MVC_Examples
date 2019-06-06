using JwtTokenAuthenticationWebApi.Auth;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Web.Http;

namespace JwtTokenAuthenticationWebApi.Controllers
{
    public class JwtTestController : ApiController
    {
        // GET api/jwttest
        public IEnumerable<string> Get()
        {
            // return username, userid and jwt token.
            string username = "username01";
            string userid = "userid01";
            AuthenticationHelper authHelper = new AuthenticationHelper();
            string jwtToken = authHelper.GenerateJwtToken(username, userid);

            JwtSecurityToken securityToken = authHelper.ValidateJwtToken(jwtToken);
            string jwtTokenUniqueName = String.Format("Jwt Token unique_name={0}", securityToken.Payload["unique_name"]);
            string jwtTokenNameId = String.Format("Jwt Token nameid={0}", securityToken.Payload["nameid"]);
            StringBuilder allKeys = new StringBuilder();
            foreach (var key in securityToken.Payload.Keys)
            {
                allKeys.Append(String.Format("Key={0}, Value={1}", key, securityToken.Payload[key]));
                allKeys.Append(" | ");
            }

            return new string[] { username, userid, jwtToken, jwtTokenUniqueName, jwtTokenNameId, allKeys.ToString() };
        }
    }
}
