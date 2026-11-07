using ApiSecurityDemo.Data;
using ApiSecurityDemo.Middleware;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddHttpClient();
builder.Services.AddSingleton<SecurityDatabase>();
builder.Services.AddSingleton<BaselineEngine>();
builder.Services.AddSingleton<IpTracker>();
builder.Services.AddSingleton<RiskScorer>();
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(LogLevel.Information);

var app = builder.Build();
_ = app.Services.GetRequiredService<BaselineEngine>();
_ = app.Services.GetRequiredService<IpTracker>();

app.UseApiSecurityMonitoring();
app.UseStaticFiles();
app.UseRouting();
app.MapControllers();
app.MapGet("/dashboard", () => Results.Redirect("/dashboard.html"));

Console.WriteLine("==============================================");
Console.WriteLine("  API Security Monitoring — Running");
Console.WriteLine("  Dashboard: http://localhost:5000/dashboard");
Console.WriteLine("==============================================");
app.Run("http://localhost:5000");
