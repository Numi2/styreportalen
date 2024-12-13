using Hangfire;
using Microsoft.EntityFrameworkCore;
using StyreportalenBackend.Data;
using StyreportalenBackend.Models;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace StyreportalenBackend.Services
{
    public class MeetingReminderService
    {
        private readonly ApplicationDbContext _context;
        private readonly IEmailSender _emailSender;

        public MeetingReminderService(ApplicationDbContext context, IEmailSender emailSender)
        {
            _context = context;
            _emailSender = emailSender;
        }

        // This method should be scheduled to run periodically (e.g., every hour)
        public async Task SendMeetingReminders()
        {
            var upcomingMeetings = await _context.Meetings
                .Include(m => m.Attendees)
                    .ThenInclude(a => a.User)
                .Where(m => m.ScheduledDateTime > DateTime.UtcNow && m.ScheduledDateTime <= DateTime.UtcNow.AddHours(24))
                .ToListAsync();

            foreach (var meeting in upcomingMeetings)
            {
                foreach (var attendee in meeting.Attendees)
                {
                    var user = attendee.User;
                    if (user != null)
                    {
                        var subject = $"Reminder: Upcoming Meeting '{meeting.Title}'";
                        var message = $"Dear {user.UserName},<br/><br/>This is a reminder for the upcoming meeting titled '<strong>{meeting.Title}</strong>' scheduled at {meeting.ScheduledDateTime.ToLocalTime()}.<br/><br/>Best regards,<br/>Styreportalen Team";

                        await _emailSender.SendEmailAsync(user.Email, subject, message);
                    }
                }
            }
        }
    }
}
