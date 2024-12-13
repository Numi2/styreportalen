using System;
using System.Collections.Generic;

namespace StyreportalenBackend.Models
{
    public class Meeting
    {
        public Guid Id { get; set; }
        public string Title { get; set; }
        public DateTime ScheduledDateTime { get; set; }
        public Guid TenantId { get; set; }
        public Tenant Tenant { get; set; }
        public ICollection<MeetingAttendee> Attendees { get; set; }
        // Additional properties as needed
    }
}
