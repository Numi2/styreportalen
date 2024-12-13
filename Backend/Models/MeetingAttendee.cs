using System;

namespace StyreportalenBackend.Models
{
    public class MeetingAttendee
    {
        public Guid Id { get; set; }
        public Guid MeetingId { get; set; }
        public Meeting Meeting { get; set; }
        public string UserId { get; set; }
        public ApplicationUser User { get; set; }
        // Additional properties as needed
    }
}
