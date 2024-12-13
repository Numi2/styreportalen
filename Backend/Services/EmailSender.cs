using Microsoft.Extensions.Configuration;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace StyreportalenBackend.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly IConfiguration _configuration;

        public EmailSender(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string message)
        {
            var smtpHost = _configuration["EmailSender:SMTPHost"];
            var smtpPort = int.Parse(_configuration["EmailSender:SMTPPort"]);
            var smtpUser = _configuration["EmailSender:SMTPUser"];
            var smtpPass = _configuration["EmailSender:SMTPPass"];

            var mail = new MailMessage();
            mail.From = new MailAddress(smtpUser);
            mail.To.Add(toEmail);
            mail.Subject = subject;
            mail.Body = message;
            mail.IsBodyHtml = true;

            using (var smtp = new SmtpClient(smtpHost, smtpPort))
            {
                smtp.Credentials = new NetworkCredential(smtpUser, smtpPass);
                smtp.EnableSsl = true;
                await smtp.SendMailAsync(mail);
            }
        }
    }
}
