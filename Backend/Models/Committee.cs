using System;
using System.Collections.Generic;

namespace StyreportalenBackend.Models
{
    public class Committee
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public Guid TenantId { get; set; }
        public Tenant Tenant { get; set; }
        public ICollection<ApplicationUser> Members { get; set; }
        public ICollection<Message> Messages { get; set; }
        // Additional properties as needed
    }
}
