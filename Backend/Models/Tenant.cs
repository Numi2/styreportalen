using System;
using System.Collections.Generic;

namespace StyreportalenBackend.Models
{
    public class Tenant
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public ICollection<ApplicationUser> Users { get; set; }
        public ICollection<Committee> Committees { get; set; }
        public ICollection<Document> Documents { get; set; }
        public ICollection<Meeting> Meetings { get; set; }
        // Additional properties as needed
    }
}
