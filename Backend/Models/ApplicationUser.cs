using Microsoft.AspNetCore.Identity;
using System;

namespace StyreportalenBackend.Models
{
    public class ApplicationUser : IdentityUser
    {
        public Guid TenantId { get; set; }
        // Additional properties as needed
    }
}
