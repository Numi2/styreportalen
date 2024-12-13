using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Linq;
using System.Security.Claims;

namespace StyreportalenBackend.Filters
{
    public class MfaRequiredAttribute : AuthorizeAttribute, IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var user = context.HttpContext.User;
            if (user.Identity.IsAuthenticated)
            {
                var roles = user.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value);
                if (roles.Contains("Administrator"))
                {
                    var mfaCompleted = user.HasClaim(c => c.Type == "MfaCompleted" && c.Value == "true");
                    if (!mfaCompleted)
                    {
                        context.Result = new ForbidResult();
                    }
                }
            }
        }
    }
}
