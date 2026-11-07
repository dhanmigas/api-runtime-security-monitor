"""Normal traffic — 500 requests to measure FPR and build baseline."""
import time,random,sys,os
sys.path.insert(0,os.path.dirname(__file__))
from config import hit,log,summary,random_ip,USER_AGENTS

TOTAL=500; DELAY_MIN=0.08; DELAY_MAX=0.4

def run():
    log(f"Normal Traffic — {TOTAL} requests"); log("Expected: ALL Allow\n")
    results=[]; user_ips=[random_ip("10.10") for _ in range(30)]
    mix=([("GET","/api/products",None,False)]*40+
         [("POST","/api/login",{"username":"admin","password":"password123"},False)]*20+
         [("POST","/api/login",{"username":"admin","password":"wrong"},False)]*5+
         [("GET","/api/users",None,True)]*20+
         [("POST","/api/data",{"msg":"hello","val":42},False)]*10+
         [("GET","/api/admin",None,True)]*5)
    random.shuffle(mix)
    for i in range(TOTAL):
        m,p,b,auth=random.choice(mix)
        status,ms,_=hit(m,p,b,ip=random.choice(user_ips),
            user_agent=random.choice(USER_AGENTS),auth="tok" if auth else None)
        results.append({"status":status,"ms":ms})
        if(i+1)%100==0:
            fp=sum(1 for r in results if r["status"] in[403,429])
            log(f"  {i+1}/{TOTAL} | FP so far: {fp}")
        time.sleep(random.uniform(DELAY_MIN,DELAY_MAX))
    s=summary("Normal Traffic — Baseline + FPR",results)
    fp=sum(1 for r in results if r["status"] in[403,429])
    fpr=round(fp/TOTAL*100,1)
    print(f"  FPR: {fp}/{TOTAL} = {fpr}%  Target ≤10%  {'✅' if fpr<=10 else '❌'}\n")
    return s

if __name__=="__main__": run()
