using ApiSecurityDemo.Data;
using ApiSecurityDemo.Models;

namespace ApiSecurityDemo.Middleware;

public class BaselineEngine
{
    private readonly Dictionary<string, EndpointBaseline> _bl = new();
    private readonly SecurityDatabase _db;
    private readonly ILogger<BaselineEngine> _log;
    private const int Warmup = 50, Learn = 500;

    public BaselineEngine(SecurityDatabase db, ILogger<BaselineEngine> log)
    {
        _db = db; _log = log;
        Seed(); Load(); _db.ExpireOldProposals();
    }

    private void Seed()
    {
        void A(string ep, double fm, double fs, double pm, double ps,
        double am, double as2, double em, double es)
     => _bl[ep] = new EndpointBaseline
     {
         Endpoint = ep,
         InWarmup = true,
         ReqFrequencyMean = fm,
         ReqFrequencyStdDev = fs,
         PayloadSizeMean = pm,
         PayloadSizeStdDev = ps,
         AuthFailureRateMean = am,
         AuthFailureRateStdDev = as2,
         ErrorRateMean = em,
         ErrorRateStdDev = es
     };

        // Tighter payload std devs so injection payloads spike the z-score faster
        A("POST /api/login", 20, 5, 80, 20, 0.05, 0.02, 0.05, 0.02);
        A("GET /api/products", 50, 10, 0, 5, 0.01, 0.005, 0.02, 0.01);
        A("GET /api/users", 15, 5, 0, 5, 0.02, 0.01, 0.03, 0.01);
        A("POST /api/data", 30, 8, 200, 50, 0.02, 0.01, 0.03, 0.01);
        A("GET /api/admin", 2, 1, 0, 5, 0.01, 0.005, 0.02, 0.01);
    }

    private void Load()
    {
        foreach (var b in _db.LoadBaselines())
        {
            _bl[b.Endpoint] = b;
            _log.LogInformation("[DB] Loaded {Ep} obs:{N}", b.Endpoint, b.ObservationCount);
        }
    }

    public EndpointBaseline GetOrCreate(string ep)
    {
        if (!_bl.TryGetValue(ep, out var b))
            _bl[ep] = b = new EndpointBaseline { Endpoint = ep, InWarmup = true };
        return b;
    }

    public bool IsInWarmup(string ep) => GetOrCreate(ep).InWarmup;

    public static double ZScore(double obs, double mean, double sd)
        => sd <= 0 ? 0 : Math.Abs(obs - mean) / sd;

    public static double StdDev(IEnumerable<double> vals)
    {
        var l = vals.ToList();
        if (l.Count < 2) return 1;
        double m = l.Average();
        return Math.Sqrt(l.Average(v => Math.Pow(v - m, 2)));
    }

    public void RecordObservation(string ep, double freq, double aggFreq, double payload,
    double auth, double err)
    {
        var b = GetOrCreate(ep);
        b.RecentFrequencies.Add(freq);
        b.RecentAggFrequencies.Add(aggFreq);
        b.RecentPayloads.Add(payload);
        b.RecentAuthFailRates.Add(auth);
        b.RecentErrorRates.Add(err);

        if (b.ObservationCount == 0)
            b.FirstObservationAt = DateTime.UtcNow;

        b.ObservationCount++;

        if (b.InWarmup && b.ObservationCount >= Warmup &&
     (DateTime.UtcNow - b.FirstObservationAt).TotalSeconds >= 65 &&
     !b.WarmupProposalSubmitted)
        {
            b.WarmupProposalSubmitted = true;

            var recentFreq = b.RecentFrequencies.TakeLast(Warmup).ToList();
            var recentPay = b.RecentPayloads.TakeLast(Warmup).ToList();
            var recentAuth = b.RecentAuthFailRates.TakeLast(Warmup).ToList();
            var recentErr = b.RecentErrorRates.TakeLast(Warmup).ToList();
            var recentAggFreq = b.RecentAggFrequencies.TakeLast(Warmup).ToList();

            b.PendingFreqMean = recentFreq.Average();
            b.PendingFreqStdDev = StdDev(recentFreq);
            b.PendingAggFreqMean = recentAggFreq.Average();
            b.PendingAggFreqStdDev = StdDev(recentAggFreq);
            b.PendingPayloadMean = recentPay.Average();
            b.PendingPayloadStdDev = StdDev(recentPay);
            b.PendingAuthMean = recentAuth.Average();
            b.PendingAuthStdDev = StdDev(recentAuth);
            b.PendingErrorMean = recentErr.Average();
            b.PendingErrorStdDev = StdDev(recentErr);

            int id = _db.InsertHitlProposal(new HitlRecord
            {
                Endpoint = b.Endpoint,
                Parameter = "InitialBaseline",
                OldMean = 0,
                ProposedMean = b.PendingFreqMean,
                OldStdDev = 0,
                ProposedStdDev = b.PendingFreqStdDev,
                ChangePercent = 0,
                ProposedAt = DateTime.UtcNow
            });

            _log.LogWarning("[HITL] Initial baseline proposal {Id} for {Ep} — endpoint stays unscored until a developer approves",
                id, b.Endpoint);
        }
        if (b.RecentFrequencies.Count > 1000)
        {
            b.RecentFrequencies.RemoveAt(0);
            b.RecentAggFrequencies.RemoveAt(0);
            b.RecentPayloads.RemoveAt(0);
            b.RecentAuthFailRates.RemoveAt(0);
            b.RecentErrorRates.RemoveAt(0);
        }

        if (b.ObservationCount % Learn == 0) Propose(b);
    }

    private void Propose(EndpointBaseline b)
    {
        ProposeParameter(b, "Frequency", b.RecentFrequencies,
            b.ReqFrequencyMean, b.ReqFrequencyStdDev);
        ProposeParameter(b, "AggFrequency", b.RecentAggFrequencies,
            b.AggFrequencyMean, b.AggFrequencyStdDev);
        ProposeParameter(b, "PayloadSize", b.RecentPayloads,
            b.PayloadSizeMean, b.PayloadSizeStdDev);
        ProposeParameter(b, "AuthFailureRate", b.RecentAuthFailRates,
            b.AuthFailureRateMean, b.AuthFailureRateStdDev);
        ProposeParameter(b, "ErrorRate", b.RecentErrorRates,
            b.ErrorRateMean, b.ErrorRateStdDev);
    }

    private void ProposeParameter(EndpointBaseline b, string parameter,
     List<double> recent, double oldMean, double oldStdDev)
    {
        if (recent.Count < 50) return;

        bool alreadyPending = _db.GetPendingApprovals()
            .Any(p => p.Endpoint == b.Endpoint && p.Parameter == parameter);
        if (alreadyPending) return;

        double nm = recent.Average();
        double ns = StdDev(recent);
        double chg = oldMean == 0 ? 0 : Math.Abs(nm - oldMean) / oldMean * 100;

        int id = _db.InsertHitlProposal(new HitlRecord
        {
            Endpoint = b.Endpoint,
            Parameter = parameter,
            OldMean = oldMean,
            ProposedMean = nm,
            OldStdDev = oldStdDev,
            ProposedStdDev = ns,
            ChangePercent = Math.Round(chg, 1),
            ProposedAt = DateTime.UtcNow
        });

        _log.LogWarning("[HITL] Proposal {Id} {Ep} [{Param}] μ {O:F2}→{N:F2} ({C:F1}%) PENDING",
            id, b.Endpoint, parameter, oldMean, nm, chg);
    }

    public bool ApplyApproval(int id, bool approved, string note)
    {
        _db.UpdateHitlDecision(id, approved, note);
        var p = _db.GetHitlById(id);
        if (p == null) return false;
        var b = GetOrCreate(p.Endpoint);

        if (!approved)
        {
            if (p.Parameter == "InitialBaseline") b.WarmupProposalSubmitted = false;
            return false;
        }

        if (p.Parameter == "InitialBaseline")
        {
            b.ReqFrequencyMean = b.PendingFreqMean;
            b.ReqFrequencyStdDev = b.PendingFreqStdDev;
            b.AggFrequencyMean = b.PendingAggFreqMean;
            b.AggFrequencyStdDev = b.PendingAggFreqStdDev;
            b.PayloadSizeMean = b.PendingPayloadMean;
            b.PayloadSizeStdDev = b.PendingPayloadStdDev;
            b.AuthFailureRateMean = b.PendingAuthMean;
            b.AuthFailureRateStdDev = b.PendingAuthStdDev;
            b.ErrorRateMean = b.PendingErrorMean;
            b.ErrorRateStdDev = b.PendingErrorStdDev;
            b.InWarmup = false;
            b.DeveloperApproved = true;
            b.LastUpdated = DateTime.UtcNow;
            _db.SaveBaseline(b);
            _log.LogInformation("[BASELINE] {Ep} initial baseline approved and applied", p.Endpoint);
            return true;
        }

        switch (p.Parameter)
        {
            case "Frequency":
                b.ReqFrequencyMean = p.ProposedMean; b.ReqFrequencyStdDev = p.ProposedStdDev; break;
            case "AggFrequency":
                b.AggFrequencyMean = p.ProposedMean; b.AggFrequencyStdDev = p.ProposedStdDev; break;
            case "PayloadSize":
                b.PayloadSizeMean = p.ProposedMean; b.PayloadSizeStdDev = p.ProposedStdDev; break;
            case "AuthFailureRate":
                b.AuthFailureRateMean = p.ProposedMean; b.AuthFailureRateStdDev = p.ProposedStdDev; break;
            case "ErrorRate":
                b.ErrorRateMean = p.ProposedMean; b.ErrorRateStdDev = p.ProposedStdDev; break;
            default: return false;
        }
        b.DeveloperApproved = true; b.LastUpdated = DateTime.UtcNow;
        _db.SaveBaseline(b);
        return true;
    }

    public IReadOnlyDictionary<string, EndpointBaseline> All => _bl;
}