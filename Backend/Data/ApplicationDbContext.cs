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
