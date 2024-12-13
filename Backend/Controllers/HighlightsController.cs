using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using StyreportalenBackend.Data;
using StyreportalenBackend.Models;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace StyreportalenBackend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class HighlightsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;

        public HighlightsController(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        // POST: api/Highlights
        [HttpPost]
        public async Task<IActionResult> CreateHighlight([FromBody] HighlightModel model)
        {
            var tenant = HttpContext.Items["Tenant"] as Tenant;
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var document = await _context.Documents.FirstOrDefaultAsync(d => d.Id == model.DocumentId && d.TenantId == tenant.Id);
            if (document == null)
                return NotFound("Document not found.");

            var highlight = new Highlight
            {
                Id = Guid.NewGuid(),
                DocumentId = model.DocumentId,
                Comment = model.Comment,
                Content = model.Content,
                Color = model.Color,
                Position = model.Position,
                CreatedAt = DateTime.UtcNow,
                UserId = userId
            };

            _context.Highlights.Add(highlight);
            await _context.SaveChangesAsync();

            return Ok(highlight);
        }

        // Additional endpoints can be populated similarly
    }

    public class HighlightModel
    {
        public Guid DocumentId { get; set; }
        public string Comment { get; set; }
        public string Content { get; set; }
        public string Color { get; set; }
        public string Position { get; set; } // JSON string representing position data
    }
}
