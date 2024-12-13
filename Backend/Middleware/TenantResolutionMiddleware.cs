using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using StyreportalenBackend.Data;
using StyreportalenBackend.Models;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace StyreportalenBackend.Middleware
{
    public class TenantResolutionMiddleware
    {
        private readonly RequestDelegate _next;

        public TenantResolutionMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, ApplicationDbContext dbContext)
        {
            // Example: Extract tenant from a custom header. Adjust as needed.
            if (context.Request.Headers.TryGetValue("X-Tenant-ID", out var tenantIdValues))
            {
                if (Guid.TryParse(tenantIdValues.First(), out var tenantId))
                {
                    var tenant = await dbContext.Tenants.FirstOrDefaultAsync(t => t.Id == tenantId);
                    if (tenant != null)
                    {
                        context.Items["Tenant"] = tenant;
                    }
                    else
                    {
                        context.Response.StatusCode = StatusCodes.Status400BadRequest;
                        await context.Response.WriteAsync("Invalid Tenant ID.");
                        return;
                    }
                }
                else
                {
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await context.Response.WriteAsync("Invalid Tenant ID format.");
                    return;
                }
            }
            else
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Tenant ID header is missing.");
                return;
            }

            // Call the next middleware in the pipeline
            await _next(context);
        }
    }
} 