using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using StyreportalenBackend.Data;
using StyreportalenBackend.Models;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace StyreportalenBackend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class MessagesController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IWebHostEnvironment _environment;

        public MessagesController(ApplicationDbContext context, UserManager<ApplicationUser> userManager, IWebHostEnvironment environment)
        {
            _context = context;
            _userManager = userManager;
            _environment = environment;
        }

        // POST: api/Messages/UploadAndSend
        [HttpPost("UploadAndSend")]
        public async Task<IActionResult> UploadAndSendMessage([FromForm] UploadAndSendMessageModel model)
        {
            var tenant = HttpContext.Items["Tenant"] as Tenant;
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var committee = await _context.Committees
                .Include(c => c.Members)
                .FirstOrDefaultAsync(c => c.Id == model.CommitteeId && c.TenantId == tenant.Id);

            if (committee == null)
                return NotFound("Committee not found.");

            // Check if user is a member of the committee
            if (!committee.Members.Any(m => m.UserId == userId))
                return Forbid("You are not a member of this committee.");

            string attachmentPath = null;
            if (model.File != null && model.File.Length > 0)
            {
                attachmentPath = Path.Combine(_environment.WebRootPath, "uploads", tenant.Id.ToString(), "committees", $"{model.CommitteeId}_{Guid.NewGuid()}{Path.GetExtension(model.File.FileName)}");
                Directory.CreateDirectory(Path.GetDirectoryName(attachmentPath));

                using (var stream = new FileStream(attachmentPath, FileMode.Create))
                {
                    await model.File.CopyToAsync(stream);
                }
            }

            var message = new Message
            {
                Id = Guid.NewGuid(),
                CommitteeId = model.CommitteeId,
                SenderUserId = userId,
                Content = model.Content,
                AttachmentPath = attachmentPath,
                SentAt = DateTime.UtcNow
            };

            _context.Messages.Add(message);
            await _context.SaveChangesAsync();

            return Ok(message);
        }

        // GET: api/Messages/{committeeId}
        [HttpGet("{committeeId}")]
        public async Task<IActionResult> GetMessages(Guid committeeId)
        {
            var tenant = HttpContext.Items["Tenant"] as Tenant;
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var committee = await _context.Committees
                .Include(c => c.Messages)
                    .ThenInclude(m => m.Sender)
                .Include(c => c.Members)
                .FirstOrDefaultAsync(c => c.Id == committeeId && c.TenantId == tenant.Id);

            if (committee == null)
                return NotFound("Committee not found.");

            // Check if user is a member of the committee
            if (!committee.Members.Any(m => m.UserId == userId))
                return Forbid("You are not a member of this committee.");

            var messages = committee.Messages
                .OrderBy(m => m.SentAt)
                .Select(m => new
                {
                    m.Id,
                    Sender = m.Sender.UserName,
                    m.Content,
                    m.SentAt,
                    m.AttachmentPath
                });

            return Ok(messages);
        }
    }

    public class UploadAndSendMessageModel
    {
        public Guid CommitteeId { get; set; }
        public string Content { get; set; }
        public IFormFile File { get; set; }
    }
}
