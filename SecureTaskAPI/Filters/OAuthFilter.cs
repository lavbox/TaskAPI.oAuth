using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http.Filters;

namespace SecureTaskAPI.Filters
{
    public class OAuthFilter : Attribute, IAuthenticationFilter
    {
        public virtual bool AllowMultiple
        {
            get { return false; }
        }

        public Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            IPrincipal principal = null;
            HttpRequestMessage request = context.Request;
            AuthenticationHeaderValue authorization = request.Headers.Authorization;
            string realmName = "TaskAPI";

            if (authorization == null)
            {
                // No authentication was attempted (for this authentication method).
                return Task.FromResult(1);
            }

            if (String.IsNullOrEmpty(authorization.Parameter))
            {
                // Authentication was attempted but failed. Set ErrorResult to indicate an error.
                context.ErrorResult = new System.Web.Http.Results.UnauthorizedResult(new List<AuthenticationHeaderValue> { GetChallengeHeader(realmName) }, context.Request);
                return Task.FromResult(1);
            }

            string token = authorization.Parameter.Replace("Bearer ", "");
            JObject jsonObject = ValidateToken(token);
            if (jsonObject != null)
            {
                var audience = (string)jsonObject["audience"];
                var expires_in = (int)jsonObject["expires_in"];
                var verified_email = (bool)jsonObject["verified_email"];
                var email = (string)jsonObject["email"];
                if (audience != ConfigurationManager.AppSettings["auth0:ClientId"] || expires_in < 1 || !verified_email)
                {
                    context.ErrorResult = new System.Web.Http.Results.UnauthorizedResult(new List<AuthenticationHeaderValue> { GetChallengeHeader(realmName) }, context.Request);
                    return Task.FromResult(1);
                }

                else
                {
                    principal = Validate(email);
                }
            }

            if (principal == null)
            {
                // Authentication was attempted but failed. Set ErrorResult to indicate an error.
                context.ErrorResult = new System.Web.Http.Results.UnauthorizedResult(new List<AuthenticationHeaderValue> { GetChallengeHeader(realmName) }, context.Request);
            }
            else
            {
                // Authentication was attempted and succeeded. Set Principal to the authenticated user.
                context.Principal = principal;
            }
            return Task.FromResult(1);
        }

        private static JObject ValidateToken(string token)
        {
            var client = new HttpClient();
            var uri = "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=" + token;
            var response = client.GetAsync(uri).Result;
            string responseBody = response.Content.ReadAsStringAsync().Result;
            var jsonObject = (JObject)JsonConvert.DeserializeObject(responseBody);
            return jsonObject;
        }

        private IPrincipal Validate(string userName)
        {
            // Create a ClaimsIdentity with all the claims for this user.
            Claim nameClaim = new Claim(ClaimTypes.Name, userName);
            List<Claim> claims = new List<Claim> { nameClaim };

            // important to set the identity this way, otherwise IsAuthenticated will be false
            ClaimsIdentity identity = new ClaimsIdentity(claims,"Basic");

            var principal = new ClaimsPrincipal(identity);
            return principal;
        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(HttpContext.Current.User.Identity.Name))
            {
                string realmName = "TaskAPI";
                AuthenticationHeaderValue header = GetChallengeHeader(realmName);
                context.Result = new System.Web.Http.Results.UnauthorizedResult(new List<AuthenticationHeaderValue> { header }, context.Request);
            }
            return Task.FromResult(0);
        }

        private static AuthenticationHeaderValue GetChallengeHeader(string realmName)
        {
            string parameter = "realm=\""+ realmName+"\"";
            AuthenticationHeaderValue header = new AuthenticationHeaderValue("Basic", parameter);
            return header;
        }
    }
}