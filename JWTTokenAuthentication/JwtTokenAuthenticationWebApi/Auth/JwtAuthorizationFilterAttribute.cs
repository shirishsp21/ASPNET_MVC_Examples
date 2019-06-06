using JwtTokenAuthenticationWebApi.Helpers;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Principal;
using System.Threading;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace JwtTokenAuthenticationWebApi.Auth
{
    // REFERENCES: 
    // 1. Authorization filter attribute - https://docs.microsoft.com/en-us/aspnet/web-api/overview/security/authentication-filters
    // 2. Generic Principal and identity - https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-create-genericprincipal-and-genericidentity-objects
    public class JwtAuthorizationFilterAttribute : AuthorizationFilterAttribute
    {
        private bool IsAuthenticated(HttpActionContext context)
        {
            // 1. Look for credentials in the request.
            HttpRequestMessage request = context.Request;
            if (!request.Headers.Contains("jwt"))
            {
                return false;
            }

            IEnumerable<string> tokenEnumerator = request.Headers.GetValues("jwt");   // NOTE: here we have used 'jwt' header key instead of Authorization.

            // 2. If there are no credentials return false.
            if (tokenEnumerator == null)
            {
                return false; 
            }

            IEnumerator<string> enumerator = tokenEnumerator.GetEnumerator();
            enumerator.MoveNext();
            string token = enumerator.Current;

            // If jwt token is NOT valid return false.
            AuthenticationHelper authHelper = new AuthenticationHelper();
            JwtSecurityToken securityToken = authHelper.ValidateJwtToken(token);
            if (securityToken == null)
            {
                return false;
            }

            // 3. Create and set principal on current thread.
            JWTAuthenticationIdentity jwtIdentity = authHelper.FetchUserIdentity(securityToken);
            string[] roles = { "All" };
            GenericPrincipal principal = new GenericPrincipal(jwtIdentity, roles);
            Thread.CurrentPrincipal = principal;

            // 4. Ensure current principal identity is using same claims as jwt identity.
            JWTAuthenticationIdentity authIdentity = Thread.CurrentPrincipal.Identity as JWTAuthenticationIdentity;
            if (authIdentity!=null && !string.IsNullOrEmpty(authIdentity.UserName))
            {
                authIdentity.UserName = jwtIdentity.UserName;
                authIdentity.UserId = jwtIdentity.UserId;
            }

            return true;
        }

        public override void OnAuthorization(HttpActionContext actionContext)
        {
            if (IsAuthenticated(actionContext))
            {
                base.OnAuthorization(actionContext);
            }
            else
            {
                actionContext.Response = HttpResponseBuilder.CreateUnauthorizedResponse(actionContext.Request);
            }

        }
    }
}