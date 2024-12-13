using System;

namespace StyreportalenBackend.Models
{
    public class Highlight
    {
        public Guid Id { get; set; }
        public Guid DocumentId { get; set; }
        public Document Document { get; set; }
        public string Comment { get; set; }
        public string Content { get; set; }
        public string Color { get; set; }
        public string Position { get; set; } // JSON string representing position data
        public DateTime CreatedAt { get; set; }
        public string UserId { get; set; }
        public ApplicationUser User { get; set; }
        // Additional properties as needed
    }
}
