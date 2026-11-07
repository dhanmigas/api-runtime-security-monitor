namespace ApiSecurityDemo.Models;

public enum RiskAction { Allow, Log, RateLimit, Block }

public class EndpointBaseline
{
    public string   Endpoint              { get; set; } = "";
    public double   ReqFrequencyMean      { get; set; } = 50;
    public double   ReqFrequencyStdDev    { get; set; } = 10;
    public double   PayloadSizeMean       { get; set; } = 300;
    public double   PayloadSizeStdDev     { get; set; } = 80;
    public double   AuthFailureRateMean   { get; set; } = 0.02;
    public double   AuthFailureRateStdDev { get; set; } = 0.01;
    public double   ErrorRateMean         { get; set; } = 0.05;
    public double   ErrorRateStdDev       { get; set; } = 0.02;
    public DateTime LastUpdated           { get; set; } = DateTime.UtcNow;
    public int      ObservationCount      { get; set; } = 0;
    public bool     DeveloperApproved     { get; set; } = true;
    public bool     InWarmup              { get; set; } = true;
    public List<double> RecentFrequencies   { get; set; } = new();
    public List<double> RecentPayloads      { get; set; } = new();
    public List<double> RecentAuthFailRates { get; set; } = new();
    public List<double> RecentErrorRates    { get; set; } = new();
    public List<double> RecentAggFrequencies { get; set; } = new();
    public DateTime FirstObservationAt { get; set; }
    public bool WarmupProposalSubmitted { get; set; }
    public double PendingFreqMean { get; set; }
    public double PendingFreqStdDev { get; set; }
    public double PendingPayloadMean { get; set; }
    public double PendingPayloadStdDev { get; set; }
    public double PendingAuthMean { get; set; }
    public double PendingAuthStdDev { get; set; }
    public double PendingErrorMean { get; set; }
    public double PendingErrorStdDev { get; set; }
    public double PendingAggFreqMean { get; set; }
    public double PendingAggFreqStdDev { get; set; }
    public double AggFrequencyMean { get; set; }
    public double AggFrequencyStdDev { get; set; }
}

public class IpRecord
{
    public string          IpAddress             { get; set; } = "";
    public Queue<DateTime> RequestTimestamps      { get; set; } = new();
    public int             TotalRequests          { get; set; } = 0;
    public int             AuthFailures           { get; set; } = 0;
    public List<double>    TimingIntervals        { get; set; } = new();
    public int             MissingUserAgentCount  { get; set; } = 0;
    public int             InvalidSessionCount    { get; set; } = 0;
    public List<string>    EndpointSequence       { get; set; } = new();
    public int             TimesWarned            { get; set; } = 0;
    public int             TimesBlocked           { get; set; } = 0;
    public DateTime?       LastBlocked            { get; set; }
    public DateTime        FirstSeen              { get; set; } = DateTime.UtcNow;
    public DateTime        LastSeen               { get; set; } = DateTime.UtcNow;
    public long            LastPayloadSize        { get; set; } = 0;

    public double AuthFailureRate =>
        TotalRequests == 0 ? 0 : (double)AuthFailures / TotalRequests;

    public int RequestsInWindow(DateTime now, int seconds = 60)
    {
        var cutoff = now.AddSeconds(-seconds);
        return RequestTimestamps.Count(t => t >= cutoff);
    }

    public double TimingVariance()
    {
        if (TimingIntervals.Count < 3) return 9999;
        double mean = TimingIntervals.Average();
        return TimingIntervals.Average(t => Math.Pow(t - mean, 2));
    }
}

public class HitlRecord
{
    public int Id { get; set; }
    public string Endpoint { get; set; } = "";
    public string Parameter { get; set; } = "Frequency";
    public double OldMean { get; set; }
    public double ProposedMean { get; set; }
    public double OldStdDev { get; set; }
    public double ProposedStdDev { get; set; }
    public double ChangePercent { get; set; }
    public string Status { get; set; } = "Pending";
    public string DeveloperNote { get; set; } = "";
    public DateTime ProposedAt { get; set; } = DateTime.UtcNow;
    public DateTime? DecidedAt { get; set; }
}

public class SecurityEvent
{
    public int      Id            { get; set; }
    public string   Ip            { get; set; } = "";
    public string   Endpoint      { get; set; } = "";
    public string   Action        { get; set; } = "";
    public double   Score         { get; set; }
    public double   L1            { get; set; }
    public double   L2            { get; set; }
    public double   L3            { get; set; }
    public double   L4            { get; set; }
    public int      StatusCode    { get; set; }
    public bool     IsKnownAttack { get; set; }
    public double   LatencyMs     { get; set; }
    public DateTime Timestamp     { get; set; } = DateTime.UtcNow;
}

public class BlacklistEntry
{
    public int      Id         { get; set; }
    public string   IpOrSubnet { get; set; } = "";
    public string   Reason     { get; set; } = "";
    public DateTime AddedAt    { get; set; } = DateTime.UtcNow;
}

public class ScorePoint
{
    public string   Endpoint  { get; set; } = "";
    public double   Score     { get; set; }
    public string   Action    { get; set; } = "";
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

public class EvalMetrics
{
    public long   TP           { get; set; }
    public long   FP           { get; set; }
    public long   FN           { get; set; }
    public long   TN           { get; set; }
    public double DetectionRate    => TP+FN==0 ? 0 : Math.Round((double)TP/(TP+FN),3);
    public double FalsePositiveRate=> FP+TN==0 ? 0 : Math.Round((double)FP/(FP+TN),3);
    public double Precision        => TP+FP==0 ? 0 : Math.Round((double)TP/(TP+FP),3);
    public double F1Score          { get {
        var p=Precision; var r=DetectionRate;
        return p+r==0 ? 0 : Math.Round(2*p*r/(p+r),3); }}
    public double AvgLatencyMs { get; set; }
}

public class EventStats
{
    public long   Total        { get; set; }
    public long   Allowed      { get; set; }
    public long   Logged       { get; set; }
    public long   RateLimited  { get; set; }
    public long   Blocked      { get; set; }
    public double AvgScore     { get; set; }
    public double AvgLatencyMs { get; set; }
}
