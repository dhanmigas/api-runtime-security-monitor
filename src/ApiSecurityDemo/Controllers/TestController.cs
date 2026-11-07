using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;

namespace ApiSecurityDemo.Controllers;

[ApiController]
[Route("api")]
public class TestController : ControllerBase
{
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest req)
    {
        if(IsSql(req.Username)||IsSql(req.Password))
            return BadRequest(new{message="Invalid input detected"});
        if(req.Username=="admin"&&req.Password=="password123")
            return Ok(new{token="demo-token",message="Login successful"});
        return Unauthorized(new{message="Invalid credentials"});
    }

    [HttpGet("products")]
    public IActionResult Products()=>Ok(new[]{
        new{id=1,name="Widget A",price=9.99},
        new{id=2,name="Widget B",price=19.99},
        new{id=3,name="Widget C",price=4.99}});

    [HttpGet("users")]
    public IActionResult Users()
    {
        if(!Request.Headers.ContainsKey("Authorization"))
            return Unauthorized(new{message="Token required"});
        return Ok(new[]{new{id=1,name="Alice"},new{id=2,name="Bob"}});
    }

    [HttpPost("data")]
    public IActionResult PostData([FromBody] DataRequest req)
    {
        if(req?.Payload!=null&&IsSql(req.Payload.ToString()!))
            return BadRequest(new{message="Invalid payload"});
        return Ok(new{message="Data received",at=DateTime.UtcNow});
    }

    [HttpGet("admin")]
    public IActionResult Admin()
    {
        if(!Request.Headers.ContainsKey("Authorization"))
            return Unauthorized(new{message="Admin requires token"});
        return Ok(new{message="Admin data",secret="confidential"});
    }

    private static bool IsSql(string s)
    {
        if(string.IsNullOrEmpty(s)) return false;
        return new[]{
           @"(--|;|\/\*|\*\/)",
            @"(OR|AND)\s+['""0-9]",
            @"UNION\s+(ALL\s+)?SELECT",
            @"DROP\s+(TABLE|DATABASE)",
            @"INSERT\s+INTO",
            @"DELETE\s+FROM",
            @"(EXEC|EXECUTE|xp_|sp_)\s*\(",
            @"CAST\s*\(|CONVERT\s*\(",
        }.Any(p=>Regex.IsMatch(s,p,RegexOptions.IgnoreCase));
    }
}

public record LoginRequest(string Username,string Password);
public record DataRequest(object? Payload);
