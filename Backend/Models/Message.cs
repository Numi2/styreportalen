using System;

namespace StyreportalenBackend.Models
{
    public class Message
    {
        public Guid Id { get; set; }
        public Guid CommitteeId { get; set; }
        public Committee Committee { get; set; }
        public string SenderUserId { get; set; }
        public ApplicationUser Sender { get; set; }
        public string Content { get; set; }
        public string AttachmentPath { get; set; } // Optional
        public DateTime SentAt { get; set; }
        // Additional properties as needed
    }
}
