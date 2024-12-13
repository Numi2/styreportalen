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
    public class CommitteesController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public CommitteesController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: api/Committees
        [HttpGet]
        public async Task<IActionResult> GetCommittees()
        {
            var tenant = HttpContext.Items["Tenant"] as Tenant;
            var committees = await _context.Committees
                .Where(c => c.TenantId == tenant.Id)
                .Include(c => c.Members)
                .ToListAsync();

            return Ok(committees);
        }

        // POST: api/Committees
        [HttpPost]
        public async Task<IActionResult> CreateCommittee([FromBody] CreateCommitteeModel model)
        {
            var tenant = HttpContext.Items["Tenant"] as Tenant;
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var committee = new Committee
            {
                Id = Guid.NewGuid(),
                Name = model.Name,
                TenantId = tenant.Id,
                Members = new List<ApplicationUser> { await _context.Users.FindAsync(userId) }
            };

            _context.Committees.Add(committee);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetCommittees), new { id = committee.Id }, committee);
        }

        // Additional endpoints: Update, Delete, AddMember, RemoveMember, etc.
    }

    public class CreateCommitteeModel
    {
        public string Name { get; set; }
    }
} 