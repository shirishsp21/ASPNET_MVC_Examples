using JwtTokenAuthenticationWebApi.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;

namespace JwtTokenAuthenticationWebApi.Controllers
{
    [JwtAuthorizationFilter]
    public class AuthTestController : ApiController
    {
        // GET api/authonly
        public IEnumerable<string> Get()
        {
            return new string[] { "authOnlyValue01", "authOnlyValue02", "authOnlyValue03", "authOnlyValue04", "authOnlyValue05" };
        }

        // GET api/authonly/5
        public string Get(int id)
        {
            return "authOnlyValue05";
        }
    }
}
