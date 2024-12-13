using System;

namespace StyreportalenBackend.Models
{
    public class DocumentVersion
    {
        public Guid Id { get; set; }
        public Guid DocumentId { get; set; }
        public Document Document { get; set; }
        public int VersionNumber { get; set; }
        public string FilePath { get; set; }
        public DateTime UploadedAt { get; set; }
        public string UploadedByUserId { get; set; }
        public ApplicationUser UploadedByUser { get; set; }
        // Additional properties as needed
    }
}
