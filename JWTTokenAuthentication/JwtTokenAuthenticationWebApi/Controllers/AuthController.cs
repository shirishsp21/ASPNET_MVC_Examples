using JwtTokenAuthenticationWebApi.Auth;
using JwtTokenAuthenticationWebApi.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace JwtTokenAuthenticationWebApi.Controllers
{
    public class AuthController : ApiController
    {
        private bool IsAuthenticated(String username, String password, out String userId)
        {
            // In actual application verify username/password is valid by querying DB.
            bool result = false;
            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
            {
                result = (username == "username01" && password == "password01");
            }

            // In actual application this would be set from User model.
            userId = "123456789";
            return result;
        }

        [HttpGet]
        [Route("api/jwttoken")]
        public HttpResponseMessage GetToken(string username, string password)
        {
            String userId = String.Empty;
            if (IsAuthenticated(username, password, out userId))
            {
                String token = new AuthenticationHelper().GenerateJwtToken(username, userId);
                return HttpResponseBuilder.CreateOKResponse(Request, token);
            }

            return HttpResponseBuilder.CreateUnauthorizedResponse(Request);
        }
    }
}
