using System.Security.Principal;

namespace JwtTokenAuthenticationWebApi.Auth
{
    public class JWTAuthenticationIdentity : GenericIdentity
    {
        public string UserName { get; set; }
        public string UserId { get; set; }

        public JWTAuthenticationIdentity(string name) : base(name)
        {
        }
    }
}