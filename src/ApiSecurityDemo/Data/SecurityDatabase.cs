using Microsoft.Data.Sqlite;
using ApiSecurityDemo.Models;

namespace ApiSecurityDemo.Data;

public class SecurityDatabase
{
    private readonly string _cs;
    private readonly ILogger<SecurityDatabase> _log;

    public SecurityDatabase(IConfiguration cfg, ILogger<SecurityDatabase> log)
    {
        _log = log;
        _cs  = $"Data Source={cfg["Database:Path"] ?? "security.db"}";
        Init();
    }

    private void Init()
    {
        using var c = Open();
        Exec(c,@"CREATE TABLE IF NOT EXISTS baselines(
            endpoint TEXT PRIMARY KEY,freq_mean REAL,freq_stddev REAL,
            payload_mean REAL,payload_stddev REAL,auth_fail_mean REAL,
            auth_fail_stddev REAL,error_mean REAL,error_stddev REAL,
            observation_count INTEGER DEFAULT 0,developer_approved INTEGER DEFAULT 1,
            last_updated TEXT)");
        Exec(c, @"CREATE TABLE IF NOT EXISTS hitl_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT,endpoint TEXT,
    parameter TEXT DEFAULT 'Frequency',
    old_mean REAL,proposed_mean REAL,
    old_stddev REAL,proposed_stddev REAL,
    change_percent REAL,status TEXT DEFAULT 'Pending',
    developer_note TEXT DEFAULT '',proposed_at TEXT,decided_at TEXT)");
        Exec(c,@"CREATE TABLE IF NOT EXISTS security_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,ip TEXT,endpoint TEXT,
            action TEXT,score REAL,l1 REAL,l2 REAL,l3 REAL,l4 REAL,
            status_code INTEGER,is_known_attack INTEGER DEFAULT 0,
            latency_ms REAL DEFAULT 0,timestamp TEXT)");
        Exec(c,@"CREATE TABLE IF NOT EXISTS blacklist(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_or_subnet TEXT NOT NULL UNIQUE,reason TEXT,added_at TEXT)");
        Exec(c,@"CREATE TABLE IF NOT EXISTS ip_reputation(
            ip TEXT PRIMARY KEY,times_warned INTEGER DEFAULT 0,
            times_blocked INTEGER DEFAULT 0,auth_failures INTEGER DEFAULT 0,
            total_requests INTEGER DEFAULT 0,first_seen TEXT,last_blocked TEXT)");
        Exec(c,@"CREATE TABLE IF NOT EXISTS score_history(
            id INTEGER PRIMARY KEY AUTOINCREMENT,endpoint TEXT,
            score REAL,action TEXT,timestamp TEXT)");
        Try(c,"ALTER TABLE security_events ADD COLUMN is_known_attack INTEGER DEFAULT 0");
        Try(c,"ALTER TABLE security_events ADD COLUMN latency_ms REAL DEFAULT 0");
        Try(c,"ALTER TABLE ip_reputation ADD COLUMN auth_failures INTEGER DEFAULT 0");
        Try(c,"ALTER TABLE ip_reputation ADD COLUMN total_requests INTEGER DEFAULT 0");
        Try(c, "ALTER TABLE ip_reputation ADD COLUMN missing_ua_count INTEGER DEFAULT 0");
        Try(c, "ALTER TABLE ip_reputation ADD COLUMN invalid_session_count INTEGER DEFAULT 0");
    }

    private static void Try(SqliteConnection c,string sql){try{Exec(c,sql);}catch{}}

    // ── Baselines ──
    public void SaveBaseline(EndpointBaseline b)
    {
        using var c=Open();
        Exec(c,@"INSERT INTO baselines VALUES(@ep,@fm,@fs,@pm,@ps,@am,@as,@em,@es,@oc,@da,@lu)
            ON CONFLICT(endpoint) DO UPDATE SET
            freq_mean=@fm,freq_stddev=@fs,payload_mean=@pm,payload_stddev=@ps,
            auth_fail_mean=@am,auth_fail_stddev=@as,error_mean=@em,error_stddev=@es,
            observation_count=@oc,developer_approved=@da,last_updated=@lu",
            ("ep",b.Endpoint),("fm",b.ReqFrequencyMean),("fs",b.ReqFrequencyStdDev),
            ("pm",b.PayloadSizeMean),("ps",b.PayloadSizeStdDev),
            ("am",b.AuthFailureRateMean),("as",b.AuthFailureRateStdDev),
            ("em",b.ErrorRateMean),("es",b.ErrorRateStdDev),
            ("oc",b.ObservationCount),("da",b.DeveloperApproved?1:0),
            ("lu",b.LastUpdated.ToString("o")));
    }

    public List<EndpointBaseline> LoadBaselines()
    {
        using var c=Open(); var list=new List<EndpointBaseline>();
        using var cmd=c.CreateCommand();
        cmd.CommandText="SELECT * FROM baselines";
        using var r=cmd.ExecuteReader();
        while(r.Read()) list.Add(new EndpointBaseline{
            Endpoint=r.GetString(0),ReqFrequencyMean=r.GetDouble(1),
            ReqFrequencyStdDev=r.GetDouble(2),PayloadSizeMean=r.GetDouble(3),
            PayloadSizeStdDev=r.GetDouble(4),AuthFailureRateMean=r.GetDouble(5),
            AuthFailureRateStdDev=r.GetDouble(6),ErrorRateMean=r.GetDouble(7),
            ErrorRateStdDev=r.GetDouble(8),ObservationCount=r.GetInt32(9),
            DeveloperApproved=r.GetInt32(10)==1,
            LastUpdated=DateTime.Parse(r.GetString(11)),InWarmup=false});
        return list;
    }

    // ── HITL ──
    public int InsertHitlProposal(HitlRecord h)
    {
        using var c = Open();
        Exec(c, @"INSERT INTO hitl_log(endpoint,parameter,old_mean,proposed_mean,
        old_stddev,proposed_stddev,change_percent,status,proposed_at)
        VALUES(@ep,@param,@om,@pm,@os,@ps,@cp,'Pending',@pa)",
            ("ep", h.Endpoint), ("param", h.Parameter), ("om", h.OldMean), ("pm", h.ProposedMean),
            ("os", h.OldStdDev), ("ps", h.ProposedStdDev),
            ("cp", h.ChangePercent), ("pa", h.ProposedAt.ToString("o")));
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT last_insert_rowid()";
        return (int)(long)cmd.ExecuteScalar()!;
    }

    public void UpdateHitlDecision(int id,bool approved,string note)
    {
        using var c=Open();
        Exec(c,"UPDATE hitl_log SET status=@st,developer_note=@dn,decided_at=@da WHERE id=@id",
            ("st",approved?"Approved":"Rejected"),("dn",note),
            ("da",DateTime.UtcNow.ToString("o")),("id",id));
    }

    public void ExpireOldProposals()
    {
        using var c=Open();
        Exec(c,"UPDATE hitl_log SET status='Expired' WHERE status='Pending' AND proposed_at<@cut",
            ("cut",DateTime.UtcNow.AddHours(-48).ToString("o")));
    }

    public List<HitlRecord> GetHitlLog(int limit = 50)
    {
        using var c = Open(); var list = new List<HitlRecord>();
        using var cmd = c.CreateCommand();
        cmd.CommandText = $"SELECT * FROM hitl_log ORDER BY proposed_at DESC LIMIT {limit}";
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(new HitlRecord
        {
            Id = r.GetInt32(0),
            Endpoint = r.GetString(1),
            Parameter = r.GetString(2),
            OldMean = r.GetDouble(3),
            ProposedMean = r.GetDouble(4),
            OldStdDev = r.GetDouble(5),
            ProposedStdDev = r.GetDouble(6),
            ChangePercent = r.GetDouble(7),
            Status = r.GetString(8),
            DeveloperNote = r.IsDBNull(9) ? "" : r.GetString(9),
            ProposedAt = DateTime.Parse(r.GetString(10)),
            DecidedAt = r.IsDBNull(11) ? null : DateTime.Parse(r.GetString(11))
        });
        return list;
    }
    public HitlRecord? GetHitlById(int id)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT * FROM hitl_log WHERE id=@id";
        cmd.Parameters.AddWithValue("@id", id);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new HitlRecord
        {
            Id = r.GetInt32(0),
            Endpoint = r.GetString(1),
            Parameter = r.GetString(2),
            OldMean = r.GetDouble(3),
            ProposedMean = r.GetDouble(4),
            OldStdDev = r.GetDouble(5),
            ProposedStdDev = r.GetDouble(6),
            ChangePercent = r.GetDouble(7),
            Status = r.GetString(8),
            DeveloperNote = r.IsDBNull(9) ? "" : r.GetString(9),
            ProposedAt = DateTime.Parse(r.GetString(10)),
            DecidedAt = r.IsDBNull(11) ? null : DateTime.Parse(r.GetString(11))
        };
    }

    public List<HitlRecord> GetPendingApprovals()=>
        GetHitlLog(200).Where(h=>h.Status=="Pending").ToList();

    // ── Events ──
    public void LogEvent(SecurityEvent e)
    {
        using var c=Open();
        Exec(c,@"INSERT INTO security_events
            (ip,endpoint,action,score,l1,l2,l3,l4,status_code,is_known_attack,latency_ms,timestamp)
            VALUES(@ip,@ep,@ac,@sc,@l1,@l2,@l3,@l4,@cd,@ia,@lm,@ts)",
            ("ip",e.Ip),("ep",e.Endpoint),("ac",e.Action),
            ("sc",e.Score),("l1",e.L1),("l2",e.L2),("l3",e.L3),("l4",e.L4),
            ("cd",e.StatusCode),("ia",e.IsKnownAttack?1:0),
            ("lm",e.LatencyMs),("ts",e.Timestamp.ToString("o")));
    }

    public List<SecurityEvent> GetRecentEvents(int limit=100)
    {
        using var c=Open(); var list=new List<SecurityEvent>();
        using var cmd=c.CreateCommand();
        cmd.CommandText=$"SELECT * FROM security_events ORDER BY timestamp DESC LIMIT {limit}";
        using var r=cmd.ExecuteReader();
        while(r.Read()) list.Add(new SecurityEvent{
            Id=r.GetInt32(0),Ip=r.GetString(1),Endpoint=r.GetString(2),
            Action=r.GetString(3),Score=r.GetDouble(4),
            L1=r.GetDouble(5),L2=r.GetDouble(6),L3=r.GetDouble(7),L4=r.GetDouble(8),
            StatusCode=r.GetInt32(9),
            IsKnownAttack=!r.IsDBNull(10)&&r.GetInt32(10)==1,
            LatencyMs=r.IsDBNull(11)?0:r.GetDouble(11),
            Timestamp=DateTime.Parse(r.GetString(12))});
        return list;
    }

    public EventStats GetEventStats()
    {
        using var c=Open();
        using var cmd=c.CreateCommand();
        cmd.CommandText=@"SELECT COUNT(*),
            SUM(CASE WHEN action='Allow' THEN 1 ELSE 0 END),
            SUM(CASE WHEN action='Log' THEN 1 ELSE 0 END),
            SUM(CASE WHEN action='RateLimit' THEN 1 ELSE 0 END),
            SUM(CASE WHEN action='Block' OR action='Block-Blacklist' THEN 1 ELSE 0 END),
            ROUND(AVG(score),3),ROUND(AVG(latency_ms),2)
            FROM security_events";
        using var r=cmd.ExecuteReader();
        if(!r.Read()) return new EventStats();
        return new EventStats{
            Total=r.IsDBNull(0)?0:Convert.ToInt64(r[0]),
            Allowed=r.IsDBNull(1)?0:Convert.ToInt64(r[1]),
            Logged=r.IsDBNull(2)?0:Convert.ToInt64(r[2]),
            RateLimited=r.IsDBNull(3)?0:Convert.ToInt64(r[3]),
            Blocked=r.IsDBNull(4)?0:Convert.ToInt64(r[4]),
            AvgScore=r.IsDBNull(5)?0:Convert.ToDouble(r[5]),
            AvgLatencyMs=r.IsDBNull(6)?0:Convert.ToDouble(r[6])};
    }

    public EvalMetrics GetEvalMetrics()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = @"SELECT
        SUM(CASE WHEN is_known_attack=1 AND action IN('Log','RateLimit','Block','Block-Blacklist') THEN 1 ELSE 0 END),
        SUM(CASE WHEN is_known_attack=0 AND action IN('RateLimit','Block','Block-Blacklist') THEN 1 ELSE 0 END),
        SUM(CASE WHEN is_known_attack=1 AND action='Allow' THEN 1 ELSE 0 END),
        SUM(CASE WHEN is_known_attack=0 AND action IN('Allow','Log') THEN 1 ELSE 0 END),
        ROUND(AVG(latency_ms),2) FROM security_events";
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return new EvalMetrics();
        return new EvalMetrics
        {
            TP = r.IsDBNull(0) ? 0 : Convert.ToInt64(r[0]),
            FP = r.IsDBNull(1) ? 0 : Convert.ToInt64(r[1]),
            FN = r.IsDBNull(2) ? 0 : Convert.ToInt64(r[2]),
            TN = r.IsDBNull(3) ? 0 : Convert.ToInt64(r[3]),
            AvgLatencyMs = r.IsDBNull(4) ? 0 : Convert.ToDouble(r[4])
        };
    }

    // ── Score history ──
    public void AddScorePoint(string ep,double score,string action)
    {
        using var c=Open();
        Exec(c,"INSERT INTO score_history(endpoint,score,action,timestamp) VALUES(@ep,@sc,@ac,@ts)",
            ("ep",ep),("sc",score),("ac",action),("ts",DateTime.UtcNow.ToString("o")));
        Exec(c,@"DELETE FROM score_history WHERE endpoint=@ep AND id NOT IN
            (SELECT id FROM score_history WHERE endpoint=@ep ORDER BY timestamp DESC LIMIT 500)",
            ("ep",ep));
    }

    public List<ScorePoint> GetScoreHistory(string ep,int mins=60)
    {
        using var c=Open(); var list=new List<ScorePoint>();
        var cut=DateTime.UtcNow.AddMinutes(-mins).ToString("o");
        using var cmd=c.CreateCommand();
        cmd.CommandText="SELECT endpoint,score,action,timestamp FROM score_history WHERE endpoint=@ep AND timestamp>@cut ORDER BY timestamp ASC";
        cmd.Parameters.AddWithValue("@ep",ep);
        cmd.Parameters.AddWithValue("@cut",cut);
        using var r=cmd.ExecuteReader();
        while(r.Read()) list.Add(new ScorePoint{
            Endpoint=r.GetString(0),Score=r.GetDouble(1),
            Action=r.GetString(2),Timestamp=DateTime.Parse(r.GetString(3))});
        return list;
    }

    // ── Blacklist ──
    public void AddToBlacklist(string ip,string reason)
    {
        using var c=Open();
        Exec(c,"INSERT OR IGNORE INTO blacklist(ip_or_subnet,reason,added_at) VALUES(@ip,@r,@at)",
            ("ip",ip),("r",reason),("at",DateTime.UtcNow.ToString("o")));
    }

    public List<BlacklistEntry> GetBlacklist()
    {
        using var c=Open(); var list=new List<BlacklistEntry>();
        using var cmd=c.CreateCommand();
        cmd.CommandText="SELECT * FROM blacklist ORDER BY added_at DESC";
        using var r=cmd.ExecuteReader();
        while(r.Read()) list.Add(new BlacklistEntry{
            Id=r.GetInt32(0),IpOrSubnet=r.GetString(1),
            Reason=r.IsDBNull(2)?"":r.GetString(2),
            AddedAt=DateTime.Parse(r.GetString(3))});
        return list;
    }

    public bool IsBlacklisted(string ip)
    {
        using var c=Open();
        var sn=Sub(ip);
        using var cmd=c.CreateCommand();
        cmd.CommandText="SELECT COUNT(*) FROM blacklist WHERE ip_or_subnet=@ip OR ip_or_subnet=@sn";
        cmd.Parameters.AddWithValue("@ip",ip);
        cmd.Parameters.AddWithValue("@sn",sn);
        return Convert.ToInt64(cmd.ExecuteScalar()!)>0;
    }

    public void RemoveFromBlacklist(string ip)
    {
        using var c=Open();
        Exec(c,"DELETE FROM blacklist WHERE ip_or_subnet=@ip",("ip",ip));
    }

    // ── IP Reputation ──
    public void SaveReputation(IpRecord rec)
    {
        using var c = Open();
        Exec(c, @"INSERT INTO ip_reputation(ip,times_warned,times_blocked,auth_failures,total_requests,first_seen,last_blocked,missing_ua_count,invalid_session_count)
        VALUES(@ip,@tw,@tb,@af,@tr,@fs,@lb,@mua,@nos)
        ON CONFLICT(ip) DO UPDATE SET
        times_warned=@tw,times_blocked=@tb,auth_failures=@af,total_requests=@tr,last_blocked=@lb,
        missing_ua_count=@mua,invalid_session_count=@nos",
            ("ip", rec.IpAddress), ("tw", rec.TimesWarned), ("tb", rec.TimesBlocked),
            ("af", rec.AuthFailures), ("tr", rec.TotalRequests),
            ("fs", rec.FirstSeen.ToString("o")), ("lb", rec.LastBlocked?.ToString("o")),
            ("mua", rec.MissingUserAgentCount), ("nos", rec.InvalidSessionCount));
    }

    public (int warned, int blocked, int authF, int total, int missingUa, int invalidSession) LoadReputation(string ip)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT times_warned,times_blocked,auth_failures,total_requests,missing_ua_count,invalid_session_count FROM ip_reputation WHERE ip=@ip";
        cmd.Parameters.AddWithValue("@ip", ip);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return (0, 0, 0, 0, 0, 0);
        return (r.GetInt32(0), r.GetInt32(1),
               r.IsDBNull(2) ? 0 : r.GetInt32(2),
               r.IsDBNull(3) ? 0 : r.GetInt32(3),
               r.IsDBNull(4) ? 0 : r.GetInt32(4),
               r.IsDBNull(5) ? 0 : r.GetInt32(5));
    }

    // ── CSV Export ──
    public string ExportEventsCsv()
    {
        var events=GetRecentEvents(10000);
        var sb=new System.Text.StringBuilder();
        sb.AppendLine("id,timestamp,ip,endpoint,action,score,l1,l2,l3,l4,status_code,is_known_attack,latency_ms");
        foreach(var e in events)
            sb.AppendLine($"{e.Id},{e.Timestamp:o},{e.Ip},{e.Endpoint},{e.Action}," +
                $"{e.Score:F3},{e.L1:F2},{e.L2:F2},{e.L3:F2},{e.L4:F2}," +
                $"{e.StatusCode},{(e.IsKnownAttack?1:0)},{e.LatencyMs:F2}");
        return sb.ToString();
    }

    // ── Helpers ──
    private static string Sub(string ip){var p=ip.Split('.');return p.Length>=3?$"{p[0]}.{p[1]}.{p[2]}":ip;}
    private SqliteConnection Open(){var c=new SqliteConnection(_cs);c.Open();return c;}
    private static void Exec(SqliteConnection c,string sql,params(string,object?)[] ps)
    {
        using var cmd=c.CreateCommand();
        cmd.CommandText=sql;
        foreach(var(k,v) in ps) cmd.Parameters.AddWithValue("@"+k,v??DBNull.Value);
        cmd.ExecuteNonQuery();
    }
}
