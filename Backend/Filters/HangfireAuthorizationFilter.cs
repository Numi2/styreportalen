using Hangfire.Dashboard;
using System.Linq;
using System.Security.Claims;

namespace StyreportalenBackend.Filters
{
    public class HangfireAuthorizationFilter : IDashboardAuthorizationFilter
    {
        public bool Authorize(DashboardContext context)
        {
            var httpContext = context.GetHttpContext();
            if (!httpContext.User.Identity.IsAuthenticated)
            {
                return false;
            }

            // Check if the user has the Administrator role
            return httpContext.User.Claims.Any(c => c.Type == ClaimTypes.Role && c.Value == "Administrator");
        }
    }
}
