using LlmSecurity.Api.Data;
using LlmSecurity.Api.Models;
using LlmSecurity.Api.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? "Data Source=runtime-data/llm-security.db;Cache=Shared;Foreign Keys=True;Default Timeout=30";
var sqlite = new SqliteConnectionStringBuilder(connectionString);
var databasePath = Path.GetFullPath(sqlite.DataSource, builder.Environment.ContentRootPath);
var databaseDirectory = Path.GetDirectoryName(databasePath);
if (!string.IsNullOrWhiteSpace(databaseDirectory))
    Directory.CreateDirectory(databaseDirectory);

sqlite.DataSource = databasePath;
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(sqlite.ConnectionString));

var dataProtectionDirectory = Path.GetFullPath(
    builder.Configuration["DataProtection:KeysPath"] ?? "data-protection",
    builder.Environment.ContentRootPath);
Directory.CreateDirectory(dataProtectionDirectory);
builder.Services
    .AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(dataProtectionDirectory))
    .SetApplicationName("llm-security-web");

builder.Services
    .AddIdentity<AppUser, IdentityRole>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.Password.RequiredLength = 8;
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = false;
        options.Password.RequireNonAlphanumeric = false;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "llm-security.auth";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.Events.OnRedirectToLogin = context =>
        WriteAuthenticationProblemAsync(
            context.HttpContext,
            StatusCodes.Status401Unauthorized,
            "로그인이 만료되었거나 인증이 필요합니다.",
            "AUTHENTICATION_REQUIRED");
    options.Events.OnRedirectToAccessDenied = context =>
        WriteAuthenticationProblemAsync(
            context.HttpContext,
            StatusCodes.Status403Forbidden,
            "요청한 작업을 수행할 권한이 없습니다.",
            "ACCESS_DENIED");
});

var frontendOrigin = builder.Configuration["Frontend:Origin"] ?? "http://localhost:5173";
builder.Services.AddCors(options =>
{
    options.AddPolicy("frontend", policy => policy
        .WithOrigins(frontendOrigin)
        .AllowAnyHeader()
        .AllowAnyMethod()
        .AllowCredentials());
});

var analyzerBaseUrl = builder.Configuration["Analyzer:BaseUrl"] ?? "http://127.0.0.1:8000";
builder.Services.AddHttpClient<PythonAnalyzerClient>(client =>
{
    client.BaseAddress = new Uri(analyzerBaseUrl);
    client.Timeout = TimeSpan.FromMinutes(30);
});
builder.Services.AddHttpClient<OpenRouterCatalogClient>(client =>
{
    client.BaseAddress = new Uri("https://openrouter.ai");
    client.Timeout = TimeSpan.FromSeconds(30);
});

builder.Services.AddScoped<AnalysisSyncService>();
builder.Services.AddProblemDetails(options =>
{
    options.CustomizeProblemDetails = context =>
    {
        context.ProblemDetails.Extensions.TryAdd(
            "traceId",
            context.HttpContext.TraceIdentifier);
    };
});
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddControllers();

var app = builder.Build();

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});
app.UseExceptionHandler();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await db.Database.MigrateAsync();
}

if (app.Environment.IsDevelopment())
    app.UseCors("frontend");
else
    app.UseHsts();

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

var spaIndex = Path.Combine(app.Environment.WebRootPath ?? "", "index.html");
if (File.Exists(spaIndex))
{
    app.MapFallback(async context =>
    {
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        context.Response.ContentType = "text/html; charset=utf-8";
        await context.Response.SendFileAsync(spaIndex);
    });
}

app.Run();

static Task WriteAuthenticationProblemAsync(
    HttpContext context,
    int status,
    string detail,
    string code)
{
    context.Response.StatusCode = status;
    var problem = new ProblemDetails
    {
        Status = status,
        Title = status == StatusCodes.Status401Unauthorized
            ? "Unauthorized"
            : "Forbidden",
        Detail = detail,
        Instance = context.Request.Path
    };
    problem.Extensions["code"] = code;
    problem.Extensions["traceId"] = context.TraceIdentifier;
    return context.Response.WriteAsJsonAsync(problem);
}
