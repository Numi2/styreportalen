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
    public class DocumentsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _environment;

        public DocumentsController(ApplicationDbContext context, IWebHostEnvironment environment)
        {
            _context = context;
            _environment = environment;
        }

        // POST: api/Documents/Upload
        [HttpPost("Upload")]
        public async Task<IActionResult> Upload([FromForm] DocumentUploadModel model)
        {
            if (model.File == null || model.File.Length == 0)
                return BadRequest("No file uploaded.");

            var tenant = HttpContext.Items["Tenant"] as Tenant;
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Check if document with the same title exists
            var existingDocument = await _context.Documents
                .Include(d => d.Versions)
                .FirstOrDefaultAsync(d => d.Title == model.Title && d.TenantId == tenant.Id);

            string filePath;
            if (existingDocument != null)
            {
                // Increment version
                int newVersionNumber = existingDocument.Versions.Count + 1;
                filePath = Path.Combine(_environment.WebRootPath, "uploads", tenant.Id.ToString(), "documents", $"{existingDocument.Id}_v{newVersionNumber}{Path.GetExtension(model.File.FileName)}");
                
                // Save new version
                var documentVersion = new DocumentVersion
                {
                    Id = Guid.NewGuid(),
                    DocumentId = existingDocument.Id,
                    VersionNumber = newVersionNumber,
                    FilePath = filePath,
                    UploadedAt = DateTime.UtcNow,
                    UploadedByUserId = userId
                };

                _context.DocumentVersions.Add(documentVersion);

                // Update current file path
                existingDocument.CurrentFilePath = filePath;
                existingDocument.UpdatedAt = DateTime.UtcNow;
            }
            else
            {
                // New document
                var documentId = Guid.NewGuid();
                filePath = Path.Combine(_environment.WebRootPath, "uploads", tenant.Id.ToString(), "documents", $"{documentId}_v1{Path.GetExtension(model.File.FileName)}");

                var document = new Document
                {
                    Id = documentId,
                    Title = model.Title,
                    CurrentFilePath = filePath,
                    TenantId = tenant.Id,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                var documentVersion = new DocumentVersion
                {
                    Id = Guid.NewGuid(),
                    DocumentId = documentId,
                    VersionNumber = 1,
                    FilePath = filePath,
                    UploadedAt = DateTime.UtcNow,
                    UploadedByUserId = userId
                };

                _context.Documents.Add(document);
                _context.DocumentVersions.Add(documentVersion);
            }

            // Ensure directory exists
            Directory.CreateDirectory(Path.GetDirectoryName(filePath));

            // Save file
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await model.File.CopyToAsync(stream);
            }

            await _context.SaveChangesAsync();

            return Ok("Document uploaded successfully.");
        }

        // Additional endpoints can be populated similarly
    }

    public class DocumentUploadModel
    {
        public string Title { get; set; }
        public IFormFile File { get; set; }
    }
}
