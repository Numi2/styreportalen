#!/bin/bash

# =====================================================================
# Styreportalen Comprehensive Codebase Setup and Population Script
# =====================================================================
# This script sets up the directory structure, initializes Backend and
# Frontend projects, installs necessary dependencies, and populates all
# required files with predefined code snippets.
# =====================================================================



# Base Directory
BASE_DIR=$(pwd)

# Function to create directories and files
create_structure() {
  echo "Setting up the Styreportalen directory structure..."

  # Create Backend Directory Structure
  mkdir -p Backend/Controllers
  mkdir -p Backend/Models
  mkdir -p Backend/Data
  mkdir -p Backend/Services
  mkdir -p Backend/Filters
  mkdir -p Backend/Migrations
  mkdir -p Backend/Properties

  # Create Frontend Directory Structure
  mkdir -p frontend/src/components
  mkdir -p frontend/src/pages
  mkdir -p frontend/src/utils
  mkdir -p frontend/public
  mkdir -p frontend/src/styles

  echo "Directory structure created successfully."
}

# Function to populate Backend files
populate_backend() {
  echo "Populating Backend files..."

  # Controllers

  ## DocumentsController.cs
  cat << 'EOF' > Backend/Controllers/DocumentsController.cs
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
EOF

  ## HighlightsController.cs
  cat << 'EOF' > Backend/Controllers/HighlightsController.cs
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
EOF

  ## MessagesController.cs
  cat << 'EOF' > Backend/Controllers/MessagesController.cs
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
EOF

  ## AuthController.cs
  cat << 'EOF' > Backend/Controllers/AuthController.cs
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using StyreportalenBackend.Data;
using StyreportalenBackend.Models;
using StyreportalenBackend.Services;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace StyreportalenBackend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailSender _emailSender;

        public AuthController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration configuration, IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _emailSender = emailSender;
        }

        // POST: api/Auth/register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var user = new ApplicationUser
            {
                UserName = model.UserName,
                Email = model.Email,
                TenantId = model.TenantId
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "Styremedlem");
                // Optionally send email confirmation
                return Ok("User registered successfully.");
            }
            return BadRequest(result.Errors);
        }

        // POST: api/Auth/login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                if (userRoles.Contains("Administrator"))
                {
                    if (await _userManager.GetTwoFactorEnabledAsync(user))
                    {
                        var token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
                        // Send token via email
                        await _emailSender.SendEmailAsync(user.Email, "MFA Token", $"Your MFA token is: {token}");

                        return Ok(new { RequiresMfa = true, Message = "MFA token sent to your email." });
                    }
                    else
                    {
                        // Administrators must have MFA enabled
                        return BadRequest("MFA is required for administrators. Please enable MFA in your profile.");
                    }
                }

                // Proceed to generate JWT token as before
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("TenantId", user.TenantId.ToString())
                };

                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }

                var jwtSettings = _configuration.GetSection("Jwt");
                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.GetValue<string>("Key")));

                var token = new JwtSecurityToken(
                    issuer: jwtSettings.GetValue<string>("Issuer"),
                    audience: jwtSettings.GetValue<string>("Audience"),
                    expires: DateTime.Now.AddMinutes(jwtSettings.GetValue<int>("DurationInMinutes")),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

                var userData = new
                {
                    user.Id,
                    user.Email,
                    user.UserName,
                    Roles = userRoles
                };

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo,
                    user = userData
                });
            }
            return Unauthorized("Invalid credentials.");
        }

        // POST: api/Auth/verify-mfa
        [HttpPost("verify-mfa")]
        public async Task<IActionResult> VerifyMfa([FromBody] VerifyMfaModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return NotFound("User not found.");

            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, model.Token);
            if (!isValid)
                return BadRequest("Invalid MFA token.");

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("TenantId", user.TenantId.ToString()),
                new Claim("MfaCompleted", "true") // Indicate MFA completion
            };

            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var jwtSettings = _configuration.GetSection("Jwt");
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.GetValue<string>("Key")));

            var token = new JwtSecurityToken(
                issuer: jwtSettings.GetValue<string>("Issuer"),
                audience: jwtSettings.GetValue<string>("Audience"),
                expires: DateTime.Now.AddMinutes(jwtSettings.GetValue<int>("DurationInMinutes")),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            var userData = new
            {
                user.Id,
                user.Email,
                user.UserName,
                Roles = userRoles
            };

            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo,
                user = userData
            });
        }
    }

    public class RegisterModel
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string UserName { get; set; }
        public Guid TenantId { get; set; }
    }

    public class LoginModel
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class VerifyMfaModel
    {
        public string Email { get; set; }
        public string Token { get; set; }
    }
}
EOF

  ## HangfireAuthorizationFilter.cs
  cat << 'EOF' > Backend/Filters/HangfireAuthorizationFilter.cs
using Hangfire.Dashboard;
using System.Linq;
using System.Security.Claims;

namespace StyreportalenBackend.Filters
{
    public class HangfireAuthorizationFilter : IDashboardAuthorizationFilter
    {
        public bool Authorize(DashboardContext context)
        {
            var httpContext = context.GetHttpContext();
            if (!httpContext.User.Identity.IsAuthenticated)
            {
                return false;
            }

            // Check if the user has the Administrator role
            return httpContext.User.Claims.Any(c => c.Type == ClaimTypes.Role && c.Value == "Administrator");
        }
    }
}
EOF

  # Models

  ## ApplicationUser.cs
  cat << 'EOF' > Backend/Models/ApplicationUser.cs
using Microsoft.AspNetCore.Identity;
using System;

namespace StyreportalenBackend.Models
{
    public class ApplicationUser : IdentityUser
    {
        public Guid TenantId { get; set; }
        // Additional properties as needed
    }
}
EOF

  ## Tenant.cs
  cat << 'EOF' > Backend/Models/Tenant.cs
using System;
using System.Collections.Generic;

namespace StyreportalenBackend.Models
{
    public class Tenant
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public ICollection<ApplicationUser> Users { get; set; }
        public ICollection<Committee> Committees { get; set; }
        public ICollection<Document> Documents { get; set; }
        public ICollection<Meeting> Meetings { get; set; }
        // Additional properties as needed
    }
}
EOF

  ## Document.cs
  cat << 'EOF' > Backend/Models/Document.cs
using System;
using System.Collections.Generic;

namespace StyreportalenBackend.Models
{
    public class Document
    {
        public Guid Id { get; set; }
        public string Title { get; set; }
        public string CurrentFilePath { get; set; }
        public Guid TenantId { get; set; }
        public Tenant Tenant { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public ICollection<DocumentVersion> Versions { get; set; }
        public ICollection<Highlight> Highlights { get; set; }
        // Additional properties as needed
    }
}
EOF

  ## DocumentVersion.cs
  cat << 'EOF' > Backend/Models/DocumentVersion.cs
using System;

namespace StyreportalenBackend.Models
{
    public class DocumentVersion
    {
        public Guid Id { get; set; }
        public Guid DocumentId { get; set; }
        public Document Document { get; set; }
        public int VersionNumber { get; set; }
        public string FilePath { get; set; }
        public DateTime UploadedAt { get; set; }
        public string UploadedByUserId { get; set; }
        public ApplicationUser UploadedByUser { get; set; }
        // Additional properties as needed
    }
}
EOF

  ## Highlight.cs
  cat << 'EOF' > Backend/Models/Highlight.cs
using System;

namespace StyreportalenBackend.Models
{
    public class Highlight
    {
        public Guid Id { get; set; }
        public Guid DocumentId { get; set; }
        public Document Document { get; set; }
        public string Comment { get; set; }
        public string Content { get; set; }
        public string Color { get; set; }
        public string Position { get; set; } // JSON string representing position data
        public DateTime CreatedAt { get; set; }
        public string UserId { get; set; }
        public ApplicationUser User { get; set; }
        // Additional properties as needed
    }
}
EOF

  ## Message.cs
  cat << 'EOF' > Backend/Models/Message.cs
using System;

namespace StyreportalenBackend.Models
{
    public class Message
    {
        public Guid Id { get; set; }
        public Guid CommitteeId { get; set; }
        public Committee Committee { get; set; }
        public string SenderUserId { get; set; }
        public ApplicationUser Sender { get; set; }
        public string Content { get; set; }
        public string AttachmentPath { get; set; } // Optional
        public DateTime SentAt { get; set; }
        // Additional properties as needed
    }
}
EOF

  ## Committee.cs
  cat << 'EOF' > Backend/Models/Committee.cs
using System;
using System.Collections.Generic;

namespace StyreportalenBackend.Models
{
    public class Committee
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public Guid TenantId { get; set; }
        public Tenant Tenant { get; set; }
        public ICollection<ApplicationUser> Members { get; set; }
        public ICollection<Message> Messages { get; set; }
        // Additional properties as needed
    }
}
EOF

  ## Meeting.cs
  cat << 'EOF' > Backend/Models/Meeting.cs
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
EOF

  ## MeetingAttendee.cs
  cat << 'EOF' > Backend/Models/MeetingAttendee.cs
using System;

namespace StyreportalenBackend.Models
{
    public class MeetingAttendee
    {
        public Guid Id { get; set; }
        public Guid MeetingId { get; set; }
        public Meeting Meeting { get; set; }
        public string UserId { get; set; }
        public ApplicationUser User { get; set; }
        // Additional properties as needed
    }
}
EOF

  # Services

  ## IEmailSender.cs
  cat << 'EOF' > Backend/Services/IEmailSender.cs
using System.Threading.Tasks;

namespace StyreportalenBackend.Services
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string toEmail, string subject, string message);
    }
}
EOF

  ## EmailSender.cs
  cat << 'EOF' > Backend/Services/EmailSender.cs
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
EOF

  ## IEncryptionService.cs
  cat << 'EOF' > Backend/Services/IEncryptionService.cs
using System;

namespace StyreportalenBackend.Services
{
    public interface IEncryptionService
    {
        string Encrypt(string plainText);
        string Decrypt(string cipherText);
    }
}
EOF

  ## EncryptionService.cs
  cat << 'EOF' > Backend/Services/EncryptionService.cs
using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace StyreportalenBackend.Services
{
    public class EncryptionService : IEncryptionService
    {
        private readonly byte[] Key;
        private readonly byte[] IV;

        public EncryptionService(IConfiguration configuration)
        {
            // Fetch from secure configuration
            Key = Convert.FromBase64String(configuration["Encryption:Key"]); // 32 bytes for AES-256
            IV = Convert.FromBase64String(configuration["Encryption:IV"]); // 16 bytes for AES
        }

        public string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return plainText;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(plainText);
                    swEncrypt.Close();
                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }

        public string Decrypt(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText))
                return cipherText;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    return srDecrypt.ReadToEnd();
                }
            }
        }
    }
}
EOF

  ## MeetingReminderService.cs
  cat << 'EOF' > Backend/Services/MeetingReminderService.cs
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
EOF

  # Filters

  ## MfaRequiredAttribute.cs
  cat << 'EOF' > Backend/Filters/MfaRequiredAttribute.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Linq;
using System.Security.Claims;

namespace StyreportalenBackend.Filters
{
    public class MfaRequiredAttribute : AuthorizeAttribute, IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var user = context.HttpContext.User;
            if (user.Identity.IsAuthenticated)
            {
                var roles = user.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value);
                if (roles.Contains("Administrator"))
                {
                    var mfaCompleted = user.HasClaim(c => c.Type == "MfaCompleted" && c.Value == "true");
                    if (!mfaCompleted)
                    {
                        context.Result = new ForbidResult();
                    }
                }
            }
        }
    }
}
EOF

  ## ApplicationDbContext.cs
  cat << 'EOF' > Backend/Data/ApplicationDbContext.cs
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using StyreportalenBackend.Models;
using StyreportalenBackend.Services;

namespace StyreportalenBackend.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        private readonly IEncryptionService _encryptionService;

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options, IEncryptionService encryptionService)
            : base(options)
        {
            _encryptionService = encryptionService;
        }

        public DbSet<Document> Documents { get; set; }
        public DbSet<DocumentVersion> DocumentVersions { get; set; }
        public DbSet<Highlight> Highlights { get; set; }
        public DbSet<Message> Messages { get; set; }
        public DbSet<Committee> Committees { get; set; }
        public DbSet<Meeting> Meetings { get; set; }
        public DbSet<MeetingAttendee> MeetingAttendees { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Example: Encrypt Email in ApplicationUser
            var converter = new ValueConverter<string, string>(
                v => _encryptionService.Encrypt(v),
                v => _encryptionService.Decrypt(v));

            modelBuilder.Entity<ApplicationUser>()
                .Property(u => u.Email)
                .HasConversion(converter);

            modelBuilder.Entity<ApplicationUser>()
                .Property(u => u.UserName)
                .HasConversion(converter);

            // Configure relationships and indexes as needed
        }
    }
}
EOF

  echo "Backend files have been populated with code snippets."
}

# Function to populate Frontend files
populate_frontend() {
  echo "Populating Frontend files..."

  # Example: AnnotateDocument.js
  cat << 'EOF' > frontend/src/components/AnnotateDocument.js
import React, { useState, useEffect } from 'react';
import { Document, Page, pdfjs } from 'react-pdf';
import { PdfLoader, PdfHighlighter, Tip, Highlight, Popup } from "react-pdf-highlighter";
import axios from '../utils/axios';
import { useParams } from 'react-router-dom';
import { CircularProgress, Typography } from '@mui/material';

// Set workerSrc
pdfjs.GlobalWorkerOptions.workerSrc = `//cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjs.version}/pdf.worker.js`;

const AnnotateDocument = () => {
  const { id } = useParams(); // Document ID
  const [pdfUrl, setPdfUrl] = useState('');
  const [highlights, setHighlights] = useState([]);

  useEffect(() => {
    // Fetch the document's current file path
    const fetchDocument = async () => {
      try {
        const response = await axios.get(`/Documents/${id}`);
        setPdfUrl(`/api/Documents/${id}/Download`);
        setHighlights(response.data.highlights || []);
      } catch (error) {
        console.error(error);
      }
    };
    fetchDocument();
  }, [id]);

  const handleAddHighlight = async (highlight) => {
    setHighlights([...highlights, highlight]);
    // Save highlight to backend
    try {
      await axios.post(`/Highlights`, highlight);
    } catch (error) {
      console.error(error);
    }
  };

  return (
    <div>
      {pdfUrl ? (
        <PdfLoader url={pdfUrl}>
          {(pdfDocument) => (
            <PdfHighlighter
              pdfDocument={pdfDocument}
              enableAreaSelection={(event) => event.altKey}
              highlights={highlights}
              onScrollChange={() => {}}
              onSelectionFinished={(position, content, hideTipAndSelection, transformSelection) => (
                <Tip
                  onOpen={transformSelection}
                  onConfirm={(comment) => {
                    handleAddHighlight({ ...position, content, comment });
                    hideTipAndSelection();
                  }}
                />
              )}
              highlightTransform={(highlight, index, setTip, hideTip, viewportToScaled, screenshot) => {
                const isTextHighlight = !highlight.content && !highlight.image;

                const component = isTextHighlight ? (
                  <Highlight
                    key={index}
                    position={highlight}
                    comment={highlight.comment}
                  />
                ) : (
                  <Popup
                    key={index}
                    position={highlight.position}
                    onMouseOver={(popupContent) => setTip(popupContent)}
                    onMouseOut={hideTip}
                  >
                    {highlight.comment.text}
                  </Popup>
                );

                return component;
              }}
            />
          )}
        </PdfLoader>
      ) : (
        <CircularProgress />
      )}
    </div>
  );
};

export default AnnotateDocument;
EOF

  # Example: CommitteeMessages.js
  cat << 'EOF' > frontend/src/components/CommitteeMessages.js
import React, { useEffect, useState } from 'react';
import axios from '../utils/axios';
import { useParams } from 'react-router-dom';
import { Container, Typography, List, ListItem, ListItemText, TextField, Button, Box, CircularProgress, Snackbar, Alert } from '@mui/material';

const CommitteeMessages = () => {
  const { id } = useParams(); // Committee ID
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [attachment, setAttachment] = useState(null);
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [notification, setNotification] = useState({ open: false, message: '', severity: 'success' });

  useEffect(() => {
    fetchMessages();
    // Optionally, set up polling or WebSockets for real-time updates
  }, [id]);

  const fetchMessages = async () => {
    setLoading(true);
    try {
      const response = await axios.get(`/Messages/${id}`);
      setMessages(response.data);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleSendMessage = async () => {
    if (!newMessage.trim() && !attachment) {
      setNotification({ open: true, message: 'Message cannot be empty.', severity: 'warning' });
      return;
    }

    setSending(true);
    try {
      const formData = new FormData();
      formData.append('CommitteeId', id);
      formData.append('Content', newMessage);
      if (attachment) {
        formData.append('File', attachment);
      }

      const response = await axios.post('/Messages/UploadAndSend', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      const newMsg = response.data;
      setMessages([...messages, {
        id: newMsg.id,
        Sender: newMsg.senderUserId, // Optionally fetch sender's username
        Content: newMsg.content,
        SentAt: newMsg.sentAt,
        attachmentPath: newMsg.attachmentPath
      }]);
      setNewMessage('');
      setAttachment(null);
      setNotification({ open: true, message: 'Message sent successfully.', severity: 'success' });
    } catch (error) {
      console.error(error);
      setNotification({ open: true, message: 'Failed to send message.', severity: 'error' });
    } finally {
      setSending(false);
    }
  };

  return (
    <Container maxWidth="md" sx={{ mt: 4 }}>
      <Typography variant="h5" gutterBottom>
        Committee Messages
      </Typography>
      {loading ? (
        <CircularProgress />
      ) : (
        <List sx={{ maxHeight: '60vh', overflow: 'auto' }}>
          {messages.map(msg => (
            <ListItem key={msg.id} alignItems="flex-start">
              <ListItemText
                primary={`${msg.Sender}: ${msg.Content}`}
                secondary={
                  <>
                    <Typography variant="caption">{new Date(msg.SentAt).toLocaleString()}</Typography>
                    {msg.AttachmentPath && (
                      <Button
                        variant="text"
                        color="primary"
                        href={msg.AttachmentPath}
                        target="_blank"
                        sx={{ ml: 2 }}
                      >
                        Download Attachment
                      </Button>
                    )}
                  </>
                }
              />
            </ListItem>
          ))}
        </List>
      )}
      <Box sx={{ mt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
        <TextField
          label="New Message"
          variant="outlined"
          fullWidth
          multiline
          rows={2}
          value={newMessage}
          onChange={(e) => setNewMessage(e.target.value)}
        />
        <input
          type="file"
          onChange={(e) => setAttachment(e.target.files[0])}
          accept=".pdf,.doc,.docx,.png,.jpg,.jpeg,.txt"
        />
        <Button variant="contained" color="primary" onClick={handleSendMessage} disabled={sending}>
          {sending ? <CircularProgress size={24} /> : 'Send'}
        </Button>
      </Box>

      {/* Notification Snackbar */}
      <Snackbar open={notification.open} autoHideDuration={6000} onClose={() => setNotification({ ...notification, open: false })}>
        <Alert onClose={() => setNotification({ ...notification, open: false })} severity={notification.severity} sx={{ width: '100%' }}>
          {notification.message}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default CommitteeMessages;
EOF

  # Frontend: Documents.js
  cat << 'EOF' > frontend/src/pages/Documents.js
import React, { useEffect, useState } from 'react';
import axios from '../utils/axios';
import { Container, Typography, List, ListItem, ListItemText, Button, Box, CircularProgress, Dialog, DialogTitle, DialogContent, DialogActions } from '@mui/material';
import { Link } from 'react-router-dom';

const Documents = () => {
  const [documents, setDocuments] = useState([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [selectedDocument, setSelectedDocument] = useState(null);

  useEffect(() => {
    fetchDocuments();
  }, []);

  const fetchDocuments = async () => {
    setLoading(true);
    try {
      const response = await axios.get('/Documents');
      setDocuments(response.data.data);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = (id, title) => {
    window.open(`/api/Documents/${id}/Download`, '_blank');
  };

  const handleOpenVersions = (id) => {
    setSelectedDocument(id);
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
    setSelectedDocument(null);
  };

  return (
    <Container maxWidth="md" sx={{ mt: 4 }}>
      <Typography variant="h4" gutterBottom>
        Documents
      </Typography>
      {loading ? (
        <CircularProgress />
      ) : (
        <List>
          {documents.map(doc => (
            <ListItem key={doc.id} divider>
              <ListItemText primary={doc.title} />
              <Button variant="outlined" onClick={() => handleDownload(doc.id, doc.title)} sx={{ mr: 1 }}>
                Download
              </Button>
              <Button variant="outlined" onClick={() => handleOpenVersions(doc.id)}>
                Versions
              </Button>
              <Button variant="outlined" component={Link} to={`/documents/${doc.id}/annotate`} sx={{ ml: 1 }}>
                Annotate
              </Button>
            </ListItem>
          ))}
        </List>
      )}

      {/* Versions Dialog */}
      <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
        <DialogTitle>Version History</DialogTitle>
        <DialogContent>
          {/* Fetch and display version history here */}
          <Typography>Version history will be displayed here.</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose}>Close</Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

export default Documents;
EOF

  # Frontend: Meetings.js
  cat << 'EOF' > frontend/src/pages/Meetings.js
import React, { useEffect, useState } from 'react';
import axios from '../utils/axios';
import { Container, Typography, List, ListItem, ListItemText, Button, CircularProgress } from '@mui/material';
import { SaveAlt, CalendarToday } from '@mui/icons-material';

const Meetings = () => {
  const [meetings, setMeetings] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchMeetings();
  }, []);

  const fetchMeetings = async () => {
    setLoading(true);
    try {
      const response = await axios.get('/Meetings');
      setMeetings(response.data.data);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleExportICS = (meetingId) => {
    window.open(`/api/Meetings/${meetingId}/ExportICS`, '_blank');
  };

  return (
    <Container maxWidth="md" sx={{ mt: 4 }}>
      <Typography variant="h4" gutterBottom>
        Meetings
      </Typography>
      {loading ? (
        <CircularProgress />
      ) : (
        <List>
          {meetings.map(meeting => (
            <ListItem key={meeting.id} divider>
              <ListItemText primary={meeting.title} secondary={new Date(meeting.scheduledDateTime).toLocaleString()} />
              <Button 
                variant="outlined" 
                onClick={() => handleExportICS(meeting.id)} 
                startIcon={<SaveAlt />}
                sx={{ mr: 1 }}
              >
                Export ICS
              </Button>
              <Button 
                variant="outlined" 
                onClick={() => handleExportICS(meeting.id)} 
                startIcon={<CalendarToday />}
              >
                Add to Calendar
              </Button>
            </ListItem>
          ))}
        </List>
      )}
    </Container>
  );
};

export default Meetings;
EOF

  # Frontend: CommitteeDetails.js
  cat << 'EOF' > frontend/src/pages/CommitteeDetails.js
import React from 'react';
import { useParams } from 'react-router-dom';
import { Container, Typography } from '@mui/material';
import CommitteeMessages from '../components/CommitteeMessages';

const CommitteeDetails = () => {
  const { id } = useParams(); // Committee ID

  return (
    <Container maxWidth="lg" sx={{ mt: 4 }}>
      {/* Existing committee details */}
      <Typography variant="h4" gutterBottom>
        Committee Details
      </Typography>
      {/* Other committee information */}

      {/* Messaging Section */}
      <CommitteeMessages />
    </Container>
  );
};

export default CommitteeDetails;
EOF

  # Frontend: axios.js
  cat << 'EOF' > frontend/src/utils/axios.js
import axios from 'axios';

const instance = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add a request interceptor to include JWT token
instance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

export default instance;
EOF

  # Additional Frontend Files can be added similarly

  echo "Backend files have been populated with code snippets."
}

# Function to initialize Backend project
initialize_backend() {
  echo "Initializing Backend (ASP.NET Core) project..."

  cd Backend

  # Initialize a new ASP.NET Core Web API project
  dotnet new webapi --no-https --output . --framework net6.0

  # Remove default Controllers
  rm Controllers/WeatherForecastController.cs || true
  rm WeatherForecast.cs || true

  echo "Backend project initialized."
  cd ..
}

# Function to initialize Frontend project
initialize_frontend() {
  echo "Initializing Frontend (React) project..."

  cd frontend

  # Initialize a new React app using Create React App
  npx create-react-app . --template cra-template-pwa

  # Install necessary dependencies
  npm install @mui/material @mui/icons-material react-router-dom axios react-pdf react-pdf-highlighter

  echo "Frontend project initialized."
  cd ..
}

# Function to install Backend dependencies
install_backend_dependencies() {
  echo "Installing Backend dependencies..."

  cd Backend

  # Restore NuGet packages
  dotnet restore

  echo "Backend dependencies installed."
  cd ..
}

# Function to install Frontend dependencies
install_frontend_dependencies() {
  echo "Installing Frontend dependencies..."

  cd frontend

  # Install NPM packages
  npm install

  echo "Frontend dependencies installed."
  cd ..
}

# Function to apply EF Core migrations
apply_migrations() {
  echo "Applying Entity Framework Core migrations..."

  cd Backend

  # Add Initial Migration
  dotnet ef migrations add InitialCreate

  # Update Database
  dotnet ef database update

  echo "Migrations applied successfully."
  cd ..
}

# Function to display completion message
completion_message() {
  echo "====================================================================="
  echo "Styreportalen codebase setup and population completed successfully!"
  echo "You can now run the Backend and Frontend applications."
  echo ""
  echo "To run the Backend:"
  echo "  cd Backend"
  echo "  dotnet run"
  echo ""
  echo "To run the Frontend:"
  echo "  cd frontend"
  echo "  npm start"
  echo "====================================================================="
}

# Execute all functions in order
create_structure
populate_backend
initialize_backend
initialize_frontend
install_backend_dependencies
install_frontend_dependencies
apply_migrations
completion_message

echo "Codebase setup and population script has run successfully."