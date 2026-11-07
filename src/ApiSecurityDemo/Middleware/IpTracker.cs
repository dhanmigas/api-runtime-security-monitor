using ApiSecurityDemo.Data;
using ApiSecurityDemo.Models;

namespace ApiSecurityDemo.Middleware;

public class IpTracker
{
    private readonly Dictionary<string,IpRecord> _recs = new();
    private readonly SecurityDatabase _db;
    private readonly ILogger<IpTracker> _log;
    private DateTime _lastClean = DateTime.UtcNow;
    private const int Win = 60;
    private readonly object _lock = new();

    public IpTracker(SecurityDatabase db, ILogger<IpTracker> log)
    { _db = db; _log = log; }

    public bool IsBlacklisted(string ip) => _db.IsBlacklisted(ip);

    public IpRecord Record(string ip, string ep, bool authFailed, long payload,
        string ua, bool hasSession, DateTime now)
    {
        lock (_lock)
        {
            if (!_recs.TryGetValue(ip, out var rec))
            {
                rec = new IpRecord { IpAddress = ip, FirstSeen = now };
                var (w, b, af, tr, mua, nos) = _db.LoadReputation(ip);
                rec.TimesWarned = w; rec.TimesBlocked = b;
                rec.AuthFailures = af; rec.TotalRequests = tr;
                rec.MissingUserAgentCount = mua; rec.InvalidSessionCount = nos;
                _recs[ip] = rec;
            }

            while (rec.RequestTimestamps.Count > 0 &&
                   rec.RequestTimestamps.Peek() < now.AddSeconds(-Win))
                rec.RequestTimestamps.Dequeue();

            rec.RequestTimestamps.Enqueue(now);
            rec.TotalRequests++;
            rec.LastSeen = now;
            rec.LastPayloadSize = payload;

            rec.EndpointSequence.Add(ep);
            if (rec.EndpointSequence.Count > 20) rec.EndpointSequence.RemoveAt(0);

            // Track auth failures cumulatively — key for slow brute force
            if (authFailed)
            {
                rec.AuthFailures++;
                // Also persist immediately so slow attacks survive window resets
                _db.SaveReputation(rec);
            }

            if (string.IsNullOrEmpty(ua)) rec.MissingUserAgentCount++;
            if (!hasSession) rec.InvalidSessionCount++;

            var ts = rec.RequestTimestamps.ToList();
            if (ts.Count >= 2)
            {
                rec.TimingIntervals.Add((ts[^1] - ts[^2]).TotalMilliseconds);
                if (rec.TimingIntervals.Count > 50) rec.TimingIntervals.RemoveAt(0);
            }

            if ((now - _lastClean).TotalMinutes > 10) Clean(now);
            return rec;
        }
    }

    public double L2Score(IpRecord r)
    {
        lock (_lock)
        {
            double s = 0;
            int n = r.RequestTimestamps.Count;
            if (n > 20) s += 0.25;
            if (n > 80) s += 0.25;

            double afr = r.AuthFailureRate;
            if (afr > 0.15) s += 0.15;
            if (afr > 0.40) s += 0.15;

            if (r.AuthFailures >= 3) s += 0.25;
            if (r.AuthFailures >= 5) s += 0.25;
            if (r.AuthFailures >= 10) s += 0.15;
            if (r.AuthFailures >= 20) s += 0.20;

            if (r.TimesBlocked > 0) s += 0.25;

            return Math.Min(s, 1.0);
        }
    }

    public double L3Score(IpRecord r)
    {
        lock (_lock)
        {
            double s = 0;
            double mua = r.TotalRequests == 0 ? 0
                : (double)r.MissingUserAgentCount / r.TotalRequests;
            if (mua > 0.3) s += 0.35;
            if (r.TimingVariance() < 200 && r.TimingIntervals.Count >= 3) s += 0.30;
            double nos = r.TotalRequests == 0 ? 0
                : (double)r.InvalidSessionCount / r.TotalRequests;
            if (nos > 0.5) s += 0.20;
            if (r.EndpointSequence.Count >= 6 &&
                r.EndpointSequence.TakeLast(6).Distinct().Count() == 1) s += 0.20;
            return Math.Min(s, 1.0);
        }
    }

    public double L4Score(string ep, long payload, DateTime now)
    {
        double s = 0;

        List<IpRecord> recent;
        lock (_lock)
        {
            recent = _recs.Values.ToList();
        }

        recent = recent.Where(r =>
            r.RequestTimestamps.Any(t => t > now.AddSeconds(-60)) &&
            r.EndpointSequence.LastOrDefault() == ep).ToList();

        if (recent.Count > 5)  s += 0.30;
        if (recent.Count > 15) s += 0.30;
        var subs = recent.Select(r => Sub(r.IpAddress)).ToList();
        int top = subs.GroupBy(x => x).Max(g => (int?)g.Count()) ?? 0;
        if (top > 3) s += 0.30;
        var pays = recent.Select(r => (double)r.LastPayloadSize).ToList();
        if (pays.Count >= 3 && BaselineEngine.StdDev(pays) < 100) s += 0.20;
        return Math.Min(s, 1.0);
    }

    public void Blacklist(IpRecord rec, string reason)
    {
        _db.AddToBlacklist(rec.IpAddress, reason);
        var sn = Sub(rec.IpAddress);
        lock (_lock)
        {
            if (_recs.Values.Count(r => Sub(r.IpAddress) == sn && r.TimesBlocked >= 2) >= 3)
                _db.AddToBlacklist(sn, $"Auto: 3+ IPs from subnet {sn}");
        }
        _db.SaveReputation(rec);
    }

    private void Clean(DateTime now)
    {
        var stale = _recs.Where(kv => (now - kv.Value.LastSeen).TotalMinutes > 30)
                         .Select(kv => kv.Key).ToList();
        foreach (var ip in stale)
        {
            if (_recs[ip].TimesBlocked > 0) _db.SaveReputation(_recs[ip]);
            _recs.Remove(ip);
        }
        _lastClean = now;
    }

    private static string Sub(string ip)
    {
        var p = ip.Split('.');
        return p.Length >= 3 ? $"{p[0]}.{p[1]}.{p[2]}" : ip;
    }
    public void IncrementWarned(IpRecord rec)
    {
        lock (_lock) { rec.TimesWarned++; }
    }

    public void IncrementBlocked(IpRecord rec, DateTime now)
    {
        lock (_lock) { rec.TimesBlocked++; rec.LastBlocked = now; }
    }
    public IReadOnlyDictionary<string, IpRecord> All => _recs;
}
