import time, random, requests
from datetime import datetime

BASE_URL = "http://localhost:5000"
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0 Mobile",
    "Mozilla/5.0 (Windows NT 10.0; rv:121.0) Gecko/20100101 Firefox/121.0",
]

def hit(method,path,body=None,ip=None,is_attack=False,user_agent=None,auth=None,timeout=10):
    url=BASE_URL+path
    headers={"Content-Type":"application/json"}
    if is_attack: headers["X-Test-Attack"]="true"
    if ip:        headers["X-Simulated-IP"]=ip
    if user_agent:headers["User-Agent"]=user_agent
    if auth:      headers["Authorization"]=f"Bearer {auth}"
    start=time.time()
    try:
        r=requests.request(method,url,json=body,headers=headers,timeout=timeout)
        return r.status_code,round((time.time()-start)*1000,2),r.text
    except requests.exceptions.ConnectionError:
        print(f"  [ERROR] Cannot connect to {BASE_URL} — is the API running?")
        return 0,0,""
    except Exception as e:
        return 0,0,str(e)

def random_ip(subnet="192.168"):
    return f"{subnet}.{random.randint(1,254)}.{random.randint(1,254)}"

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def summary(scenario,results):
    total=len(results)
    blocked=sum(1 for r in results if r["status"] in[403,429])
    allowed=sum(1 for r in results if r["status"]==200)
    errors =sum(1 for r in results if r["status"]==0)
    avg_ms =round(sum(r["ms"] for r in results if r["ms"]>0)/max(1,total-errors),2)
    print(f"\n{'='*55}")
    print(f"  {scenario}")
    print(f"{'='*55}")
    print(f"  Total:       {total}")
    print(f"  Blocked 403: {sum(1 for r in results if r['status']==403)}")
    print(f"  Rate Ltd 429:{sum(1 for r in results if r['status']==429)}")
    print(f"  Allowed 200: {allowed}")
    print(f"  Auth fail:   {sum(1 for r in results if r['status']==401)}")
    print(f"  Errors:      {errors}")
    print(f"  Avg latency: {avg_ms} ms")
    print(f"{'='*55}\n")
    return{"scenario":scenario,"total":total,"blocked":blocked,
           "allowed":allowed,"errors":errors,"avg_ms":avg_ms}
