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

    /// <summary>
    /// Retrieve a specific annotation by its ID.
    /// </summary>
    /// <param name="id">Annotation ID</param>
    /// <returns>Annotation details</returns>
    [HttpGet("{id}")]
    public async Task<IActionResult> GetAnnotation(Guid id)
    {
        var tenant = HttpContext.Items["Tenant"] as Tenant;
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        var annotation = await _context.DocumentAnnotations
            .FirstOrDefaultAsync(a => a.Id == id && a.Document.TenantId == tenant.Id);

        if (annotation == null)
            return NotFound();

        // Ensure the annotation belongs to the requesting user or the user has appropriate roles
        if (annotation.UserId != userId && !User.IsInRole("Administrator"))
            return Forbid();

        return Ok(annotation);
    }

    /// <summary>
    /// Retrieve all annotations for a specific document.
    /// </summary>
    /// <param name="documentId">Document ID</param>
    /// <returns>List of annotations</returns>
    [HttpGet("document/{documentId}")]
    public async Task<IActionResult> GetAnnotationsForDocument(Guid documentId)
    {
        var tenant = HttpContext.Items["Tenant"] as Tenant;
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        var document = await _context.Documents
            .Include(d => d.DocumentAnnotations)
            .FirstOrDefaultAsync(d => d.Id == documentId && d.TenantId == tenant.Id);

        if (document == null)
            return NotFound("Document not found.");

        var annotations = document.DocumentAnnotations
            .Where(a => a.UserId == userId || User.IsInRole("Administrator"))
            .ToList();

        return Ok(annotations);
    }

    /// <summary>
    /// Update an existing annotation.
    /// </summary>
    /// <param name="id">Annotation ID</param>
    /// <param name="model">Updated content</param>
    /// <returns>Updated annotation</returns>
    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateAnnotation(Guid id, [FromBody] UpdateAnnotationModel model)
    {
        var tenant = HttpContext.Items["Tenant"] as Tenant;
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        var annotation = await _context.DocumentAnnotations
            .Include(a => a.Document)
            .FirstOrDefaultAsync(a => a.Id == id && a.Document.TenantId == tenant.Id);

        if (annotation == null)
            return NotFound();

        // Ensure only the owner or an administrator can update the annotation
        if (annotation.UserId != userId && !User.IsInRole("Administrator"))
            return Forbid();

        annotation.Content = model.Content;
        annotation.UpdatedAt = DateTime.UtcNow;

        _context.DocumentAnnotations.Update(annotation);
        await _context.SaveChangesAsync();

        return Ok(annotation);
    }

    /// <summary>
    /// Delete an annotation.
    /// </summary>
    /// <param name="id">Annotation ID</param>
    /// <returns>Status message</returns>
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteAnnotation(Guid id)
    {
        var tenant = HttpContext.Items["Tenant"] as Tenant;
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        var annotation = await _context.DocumentAnnotations
            .Include(a => a.Document)
            .FirstOrDefaultAsync(a => a.Id == id && a.Document.TenantId == tenant.Id);

        if (annotation == null)
            return NotFound();

        // Ensure only the owner or an administrator can delete the annotation
        if (annotation.UserId != userId && !User.IsInRole("Administrator"))
            return Forbid();

        _context.DocumentAnnotations.Remove(annotation);
        await _context.SaveChangesAsync();

        return Ok("Annotation deleted successfully.");
    }

    // Additional endpoints for retrieving, editing, deleting annotations
}

public class UpdateAnnotationModel
{
    public string Content { get; set; }
} 