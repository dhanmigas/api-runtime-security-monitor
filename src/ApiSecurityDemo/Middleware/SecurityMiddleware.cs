using System.Diagnostics;
using ApiSecurityDemo.Data;
using ApiSecurityDemo.Models;

namespace ApiSecurityDemo.Middleware;

public class SecurityMiddleware
{
    private readonly RequestDelegate _next;
    private readonly BaselineEngine _bl;
    private readonly IpTracker _ip;
    private readonly RiskScorer _sc;
    private readonly SecurityDatabase _db;
    private readonly ILogger<SecurityMiddleware> _log;
    private readonly Dictionary<(string Ip, string Ep), Queue<DateTime>> _freqByIp = new();
    private readonly Dictionary<string, Queue<DateTime>> _freqAgg = new();
    private readonly object _freqLock = new();

    public SecurityMiddleware(RequestDelegate next, BaselineEngine bl,
        IpTracker ip, RiskScorer sc, SecurityDatabase db,
        ILogger<SecurityMiddleware> log)
    { _next = next; _bl = bl; _ip = ip; _sc = sc; _db = db; _log = log; }

    public async Task InvokeAsync(HttpContext ctx)
    {
        if (ctx.Request.Path.StartsWithSegments("/dashboard") ||
            ctx.Request.Path.StartsWithSegments("/wwwroot") ||
            ctx.Request.Path.StartsWithSegments("/favicon"))
        { await _next(ctx); return; }

        var sw = Stopwatch.StartNew();
        var now = DateTime.UtcNow;

        var ip = ctx.Request.Headers["X-Simulated-IP"].FirstOrDefault()
              ?? ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault()
              ?? ctx.Connection.RemoteIpAddress?.ToString()
              ?? "unknown";

        var ep = $"{ctx.Request.Method} {ctx.Request.Path}";
        bool isAttack = ctx.Request.Headers.ContainsKey("X-Test-Attack");

        if (_ip.IsBlacklisted(ip))
        {
            sw.Stop();
            Log(ip, ep, "Block-Blacklist", 1, 0, 0, 0, 0, 403, isAttack, sw.Elapsed.TotalMilliseconds);
            ctx.Response.StatusCode = 403;
            await ctx.Response.WriteAsync("Forbidden");
            return;
        }

        var payload = ctx.Request.ContentLength ?? 0;
        var ua = ctx.Request.Headers.UserAgent.ToString();
        var hasSess = ctx.Request.Cookies.ContainsKey(".AspNetCore.Session")
                   || ctx.Request.Headers.ContainsKey("Authorization");

        double freq, aggFreq;
        lock (_freqLock)
        {
            var ipKey = (ip, ep);
            if (!_freqByIp.ContainsKey(ipKey)) _freqByIp[ipKey] = new Queue<DateTime>();
            var qIp = _freqByIp[ipKey];
            while (qIp.Count > 0 && qIp.Peek() < now.AddSeconds(-60)) qIp.Dequeue();
            qIp.Enqueue(now);
            freq = qIp.Count;

            if (!_freqAgg.ContainsKey(ep)) _freqAgg[ep] = new Queue<DateTime>();
            var qAgg = _freqAgg[ep];
            while (qAgg.Count > 0 && qAgg.Peek() < now.AddSeconds(-60)) qAgg.Dequeue();
            qAgg.Enqueue(now);
            aggFreq = qAgg.Count;
        }

        var rec = _ip.Record(ip, ep, false, payload, ua, hasSess, now);

        if (_bl.IsInWarmup(ep))
        {
            sw.Stop();
            await _next(ctx);
            _bl.RecordObservation(ep, freq, aggFreq, payload, rec.AuthFailureRate, 0);
            return;
        }

        var b = _bl.GetOrCreate(ep);
        double recentErr = b.RecentErrorRates.Count == 0 ? 0 : b.RecentErrorRates.TakeLast(50).Average();
        double l1 = _sc.L1Score(freq, aggFreq, payload, rec.AuthFailureRate, recentErr, b);
        double l2 = _ip.L2Score(rec);
        double l3 = _ip.L3Score(rec);
        double l4 = _ip.L4Score(ep, payload, now);
        double fs = _sc.Combine(l1, l2, l3, l4);
        var dec = DecisionEngine.Decide(fs);
        // Stop timer after scoring — measures only middleware processing
        sw.Stop();
        double latencyMs = sw.Elapsed.TotalMilliseconds;

        _log.LogInformation(
            "[{D}] {Ip} {Ep} Score:{S:F3} L1:{L1:F2} L2:{L2:F2} L3:{L3:F2} L4:{L4:F2} {A}",
            dec, ip, ep, fs, l1, l2, l3, l4, isAttack ? "[ATTACK]" : "");

        switch (dec)
        {
            case RiskAction.Allow:
                await _next(ctx);
                var postStatus = ctx.Response.StatusCode;

                if (postStatus == 401 || postStatus == 400)
                {
                    var updatedRec = _ip.Record(ip, ep, true, payload, ua, hasSess, now); // fresh record
                    var newL2 = _ip.L2Score(updatedRec);   // must use updatedRec, not rec
                    var newFs = _sc.Combine(l1, newL2, l3, l4);
                    var newDec = DecisionEngine.Decide(newFs);

                    if (newDec != RiskAction.Allow)
                    {
                        Log(ip, ep, newDec.ToString(), newFs, l1, newL2, l3, l4, postStatus, isAttack, latencyMs);
                        break;
                    }
                }

                Log(ip, ep, "Allow", fs, l1, l2, l3, l4, postStatus, isAttack, latencyMs);
                break;
            case RiskAction.Log:
                ctx.Response.Headers["X-Security-Flag"] = "monitored";
                await _next(ctx);
                var logStatus = ctx.Response.StatusCode;
                if (logStatus == 401 || logStatus == 400)
                    _ip.Record(ip, ep, true, payload, ua, hasSess, now); // keep AuthFailures live once in Log tier
                Log(ip, ep, "Log", fs, l1, l2, l3, l4, logStatus, isAttack, latencyMs);
                break;

            case RiskAction.RateLimit:
                _ip.IncrementWarned(rec);
                Log(ip, ep, "RateLimit", fs, l1, l2, l3, l4, 429, isAttack, latencyMs);
                ctx.Response.StatusCode = 429;
                ctx.Response.Headers["Retry-After"] = "60";
                await ctx.Response.WriteAsync("Too Many Requests");
                return;

            case RiskAction.Block:
                _ip.IncrementBlocked(rec, now);
                if (rec.TimesBlocked >= 3) _ip.Blacklist(rec, "Auto-blocked");
                Log(ip, ep, "Block", fs, l1, l2, l3, l4, 403, isAttack, latencyMs);
                ctx.Response.StatusCode = 403;
                await ctx.Response.WriteAsync("Forbidden");
                return;
        }

        bool authFailed = ctx.Response.StatusCode == 401;
        double errRate = ctx.Response.StatusCode >= 400 ? 1.0 : 0.0;
        _bl.RecordObservation(ep, freq, aggFreq, payload,
            authFailed ? 1.0 : rec.AuthFailureRate, errRate);
        _db.AddScorePoint(ep, fs, dec.ToString());
    }

    private void Log(string ip, string ep, string action,
        double score, double l1, double l2, double l3, double l4,
        int code, bool isAttack, double ms)
    {
        _db.LogEvent(new SecurityEvent
        {
            Ip = ip,
            Endpoint = ep,
            Action = action,
            Score = score,
            L1 = l1,
            L2 = l2,
            L3 = l3,
            L4 = l4,
            StatusCode = code,
            IsKnownAttack = isAttack,
            LatencyMs = ms,
            Timestamp = DateTime.UtcNow
        });
    }
}

public static class SecurityMiddlewareExt
{
    public static IApplicationBuilder UseApiSecurityMonitoring(this IApplicationBuilder app)
        => app.UseMiddleware<SecurityMiddleware>();
}