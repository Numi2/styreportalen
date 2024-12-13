using System;
using System.Collections.Generic;

namespace StyreportalenBackend.Models
{
    public class Document
    {
        public Guid Id { get; set; }
        public string Title { get; set; }
        public string CurrentFilePath { get; set; }
        public Guid TenantId { get; set; }
        public Tenant Tenant { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public ICollection<DocumentVersion> Versions { get; set; }
        public ICollection<Highlight> Highlights { get; set; }
        // Additional properties as needed
    }
}
