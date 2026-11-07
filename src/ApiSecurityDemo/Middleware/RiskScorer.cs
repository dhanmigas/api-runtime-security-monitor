using ApiSecurityDemo.Models;

namespace ApiSecurityDemo.Middleware;

public class RiskScorer
{
    private readonly bool _l2, _l3, _l4;
    private const double W1 = 0.35;
    private const double WF=0.35,WA=0.30,WP=0.20,WE=0.15;

    public RiskScorer(IConfiguration cfg)
    {
        _l2=cfg.GetValue<bool>("Detection:EnableL2",true);
        _l3=cfg.GetValue<bool>("Detection:EnableL3",true);
        _l4=cfg.GetValue<bool>("Detection:EnableL4",true);
    }

    public double L1Score(double freq, double aggFreq, double payload, double auth, double err, EndpointBaseline b)
    {
        double dfIp = BaselineEngine.ZScore(freq, b.ReqFrequencyMean, b.ReqFrequencyStdDev);
        double dfAgg = BaselineEngine.ZScore(aggFreq, b.AggFrequencyMean, b.AggFrequencyStdDev);
        double df = Math.Max(dfIp, dfAgg);   // either signal alone can trigger
        double dp = BaselineEngine.ZScore(payload, b.PayloadSizeMean, b.PayloadSizeStdDev);
        double da = BaselineEngine.ZScore(auth, b.AuthFailureRateMean, b.AuthFailureRateStdDev);
        double de = BaselineEngine.ZScore(err, b.ErrorRateMean, b.ErrorRateStdDev);

        return Math.Min(WF * df + WA * da + WP * dp + WE * de, 1.0);
    }

    public double Combine(double l1, double l2, double l3, double l4)
    {
        double s = W1 * l1;
        int active = (_l2 ? 1 : 0) + (_l3 ? 1 : 0) + (_l4 ? 1 : 0);
        if (active == 0) return Math.Min(l1, 1.0);
        double w = (1.0 - W1) / active;
        if (_l2) s += w * l2; if (_l3) s += w * l3; if (_l4) s += w * l4;
        return Math.Min(s, 1.0);
    }

    public bool L2Enabled=>_l2;
    public bool L3Enabled=>_l3;
    public bool L4Enabled=>_l4;
    public string ActiveLayers(){
        var l=new List<string>{"L1"};
        if(_l2)l.Add("L2"); if(_l3)l.Add("L3"); if(_l4)l.Add("L4");
        return string.Join("+",l);}
}

public static class DecisionEngine
{
    public static RiskAction Decide(double s) => s switch {
        <0.30 => RiskAction.Allow,
        <0.60 => RiskAction.Log,
        <0.85 => RiskAction.RateLimit,
        _     => RiskAction.Block };
}
