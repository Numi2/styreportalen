using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

[Route("api/[controller]")]
[ApiController]
[Authorize]
public class AnnotationsController : ControllerBase
{
    private readonly ApplicationDbContext _context;

    public AnnotationsController(ApplicationDbContext context)
    {
        _context = context;
    }

    [HttpPost]
    public async Task<IActionResult> AddAnnotation([FromBody] AnnotationModel model)
    {
        var tenant = HttpContext.Items["Tenant"] as Tenant;
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        var document = await _context.Documents.FirstOrDefaultAsync(d => d.Id == model.DocumentId && d.TenantId == tenant.Id);
        if (document == null)
            return NotFound();

        var annotation = new DocumentAnnotation
        {
            Id = Guid.NewGuid(),
            Content = model.Content,
            DocumentId = document.Id,
            UserId = userId,
            CreatedAt = DateTime.UtcNow
        };

        _context.DocumentAnnotations.Add(annotation);
        await _context.SaveChangesAsync();

        return Ok(annotation);
    }

    // Additional endpoints for retrieving, editing, deleting annotations
}

public class AnnotationModel
{
    public Guid DocumentId { get; set; }
    public string Content { get; set; }
}