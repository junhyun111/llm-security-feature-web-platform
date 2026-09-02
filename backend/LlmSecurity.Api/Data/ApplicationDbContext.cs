using LlmSecurity.Api.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace LlmSecurity.Api.Data;

public sealed class ApplicationDbContext(
    DbContextOptions<ApplicationDbContext> options)
    : IdentityDbContext<AppUser>(options)
{
    public DbSet<AnalysisJob> AnalysisJobs => Set<AnalysisJob>();
    public DbSet<AnalysisFinding> AnalysisFindings => Set<AnalysisFinding>();
    public DbSet<PatchBatch> PatchBatches => Set<PatchBatch>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<AppUser>(entity =>
        {
            entity.Property(x => x.DisplayName).HasMaxLength(120);
            entity.HasIndex(x => x.Email);
        });

        builder.Entity<AnalysisJob>(entity =>
        {
            entity.HasKey(x => x.Id);
            entity.Property(x => x.AnalyzerJobId).HasMaxLength(64);
            entity.Property(x => x.ProjectName).HasMaxLength(200);
            entity.Property(x => x.ModelId).HasMaxLength(200);
            entity.Property(x => x.Status).HasMaxLength(32);
            entity.Property(x => x.Message).HasMaxLength(500);
            entity.HasIndex(x => x.AnalyzerJobId).IsUnique();
            entity.HasIndex(x => new { x.UserId, x.CreatedAt });
            entity.HasOne(x => x.User)
                .WithMany(x => x.AnalysisJobs)
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<AnalysisFinding>(entity =>
        {
            entity.HasKey(x => x.Id);
            entity.Property(x => x.AnalyzerFindingId).HasMaxLength(200);
            entity.Property(x => x.Title).HasMaxLength(500);
            entity.Property(x => x.FilePath).HasMaxLength(2_000);
            entity.Property(x => x.FunctionName).HasMaxLength(500);
            entity.Property(x => x.Verdict).HasMaxLength(32);
            entity.HasIndex(x => new { x.AnalysisJobId, x.AnalyzerFindingId })
                .IsUnique();
            entity.HasOne(x => x.AnalysisJob)
                .WithMany(x => x.Findings)
                .HasForeignKey(x => x.AnalysisJobId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<PatchBatch>(entity =>
        {
            entity.HasKey(x => x.Id);
            entity.Property(x => x.AnalyzerPatchId).HasMaxLength(200);
            entity.Property(x => x.Status).HasMaxLength(32);
            entity.HasIndex(x => x.AnalysisJobId).IsUnique();
            entity.HasOne(x => x.AnalysisJob)
                .WithOne(x => x.PatchBatch)
                .HasForeignKey<PatchBatch>(x => x.AnalysisJobId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
