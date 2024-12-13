using System.Threading.Tasks;

namespace StyreportalenBackend.Services
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string toEmail, string subject, string message);
    }
}
