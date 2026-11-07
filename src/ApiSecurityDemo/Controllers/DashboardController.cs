using Microsoft.AspNetCore.Mvc;
using ApiSecurityDemo.Data;
using ApiSecurityDemo.Middleware;
using ApiSecurityDemo.Models;

namespace ApiSecurityDemo.Controllers;

[ApiController]
[Route("dashboard/api")]
public class DashboardController : ControllerBase
{
    private readonly SecurityDatabase _db;
    private readonly BaselineEngine   _bl;
    private readonly IpTracker        _ip;
    private readonly RiskScorer       _sc;

    public DashboardController(SecurityDatabase db,BaselineEngine bl,
        IpTracker ip,RiskScorer sc)
    {_db=db;_bl=bl;_ip=ip;_sc=sc;}

    [HttpGet("stats")]
    public IActionResult Stats()
    {
        var s=_db.GetEventStats();
        return Ok(new{
            total=s.Total,allowed=s.Allowed,logged=s.Logged,
            rateLimited=s.RateLimited,blocked=s.Blocked,
            avgScore=s.AvgScore,avgLatencyMs=s.AvgLatencyMs,
            pendingHitl=_db.GetPendingApprovals().Count,
            blacklistCount=_db.GetBlacklist().Count,
            activeLayers=_sc.ActiveLayers()});
    }

    [HttpGet("metrics")]
    public IActionResult Metrics()=>Ok(_db.GetEvalMetrics());

    [HttpGet("hitl")]
    public IActionResult Hitl()=>Ok(_db.GetHitlLog(100));

    [HttpGet("hitl/pending")]
    public IActionResult Pending()=>Ok(_db.GetPendingApprovals());

    [HttpPost("hitl/{id}/decide")]
    public IActionResult Decide(int id,[FromBody] HitlDecision req)
    {
        bool applied=_bl.ApplyApproval(id,req.Approved,req.Note);
        return Ok(new{success=true,applied,
            message=req.Approved?"Baseline approved and applied":"Baseline rejected"});
    }

    [HttpGet("events")]
    public IActionResult Events()=>Ok(_db.GetRecentEvents(100));

    [HttpGet("baselines")]
    public IActionResult Baselines()=>Ok(_bl.All.Select(kv=>new{
        endpoint=kv.Key,freqMean=kv.Value.ReqFrequencyMean,
        freqStdDev=kv.Value.ReqFrequencyStdDev,
        payloadMean=kv.Value.PayloadSizeMean,
        authFailMean=kv.Value.AuthFailureRateMean,
        observations=kv.Value.ObservationCount,
        approved=kv.Value.DeveloperApproved,
        inWarmup=kv.Value.InWarmup,
        lastUpdated=kv.Value.LastUpdated}));

    [HttpGet("ips")]
    public IActionResult Ips()=>Ok(_ip.All.Select(kv=>new{
        ip=kv.Key,
        requestsIn60s = kv.Value.RequestsInWindow(DateTime.UtcNow, 60),
        totalRequests =kv.Value.TotalRequests,
        authFailureRate=Math.Round(kv.Value.AuthFailureRate*100,1),
        timingVarianceMs=Math.Round(kv.Value.TimingVariance(),0),
        timesWarned=kv.Value.TimesWarned,
        timesBlocked=kv.Value.TimesBlocked,
        firstSeen=kv.Value.FirstSeen}));

    [HttpGet("score-history")]
    public IActionResult ScoreHistory([FromQuery] string endpoint,[FromQuery] int minutes=60)
        =>Ok(_db.GetScoreHistory(endpoint,minutes));

    [HttpGet("score-history/endpoints")]
    public IActionResult Endpoints()=>Ok(_bl.All.Keys.OrderBy(k=>k));

    [HttpGet("blacklist")]
    public IActionResult Blacklist()=>Ok(_db.GetBlacklist());

    [HttpPost("blacklist/add")]
    public IActionResult AddBl([FromBody] BlRequest req)
    {
        _db.AddToBlacklist(req.IpOrSubnet,req.Reason);
        return Ok(new{message=$"{req.IpOrSubnet} added"});
    }

    [HttpPost("blacklist/remove")]
    public IActionResult RemBl([FromBody] BlRequest req)
    {
        _db.RemoveFromBlacklist(req.IpOrSubnet);
        return Ok(new{message=$"{req.IpOrSubnet} removed"});
    }

    [HttpGet("export/events.csv")]
    public IActionResult ExportCsv()
        =>File(System.Text.Encoding.UTF8.GetBytes(_db.ExportEventsCsv()),
            "text/csv",$"security_events_{DateTime.UtcNow:yyyyMMdd_HHmm}.csv");

    [HttpGet("config")]
    public IActionResult Config()=>Ok(new{
        activeLayers=_sc.ActiveLayers(),
        l2=_sc.L2Enabled,l3=_sc.L3Enabled,l4=_sc.L4Enabled,
        note="Edit Detection section in appsettings.json and restart to change layers"});

    // Attack simulator
    [HttpPost("simulate/{scenario}")]
    public async Task<IActionResult> Simulate(string scenario,
        [FromServices] IHttpClientFactory http)
    {
        var client=http.CreateClient();
        var base_=  $"{Request.Scheme}://{Request.Host}";
        var results=new List<string>();

        async Task Hit(string m,string path,object? body=null,string? ip=null,bool atk=false)
        {
            var msg=new HttpRequestMessage(new HttpMethod(m),base_+path);
            if(body!=null) msg.Content=JsonContent.Create(body);
            if(ip!=null)   msg.Headers.Add("X-Simulated-IP",ip);
            if(atk)        msg.Headers.Add("X-Test-Attack","true");
            try{var r=await client.SendAsync(msg);results.Add($"{m} {path} → {(int)r.StatusCode}");}
            catch(Exception ex){results.Add($"Error: {ex.Message}");}
        }

        switch(scenario.ToLower())
        {
            case "credential-stuffing":
                for(int i=0;i<30;i++)
                    await Hit("POST","/api/login",new{username="admin",password=$"wrong{i}"},"10.0.0.1",true);
                break;
            case "data-scraping":
                for(int i=0;i<40;i++)
                    await Hit("GET","/api/products",null,"10.0.0.2",true);
                break;
            case "slow-brute-force":
                for(int i=0;i<15;i++){
                    await Hit("POST","/api/login",new{username="admin",password=$"try{i}"},"10.0.0.3",true);
                    await Task.Delay(200);}
                break;
            case "bot-flood":
                await Task.WhenAll(Enumerable.Range(1,20).Select(i=>
                    Hit("GET","/api/products",null,$"10.0.{i}.1",true)));
                break;
            case "sql-injection":
                var injs=new[]{
                    new{username="admin' OR '1'='1",password="x"},
                    new{username="' UNION SELECT * FROM users --",password="x"},
                    new{username="admin'; DROP TABLE users; --",password="x"},
                    new{username=new string('A',2000)+"' OR '1'='1",password="x"},
                };
                foreach(var inj in injs) await Hit("POST","/api/login",inj,"10.0.0.5",true);
                await Hit("POST","/api/data",
                    new{payload="' OR 1=1; DROP TABLE users;--"+new string('X',4000)},
                    "10.0.0.5",true);
                break;
            case "normal":
                for(int i=0;i<10;i++){
                    await Hit("GET","/api/products");
                    await Hit("POST","/api/login",new{username="admin",password="password123"});
                    await Task.Delay(100);}
                break;
        }

        return Ok(new{scenario,requests=results.Count,results});
    }
}

public record HitlDecision(bool Approved,string Note);
public record BlRequest(string IpOrSubnet,string Reason);
