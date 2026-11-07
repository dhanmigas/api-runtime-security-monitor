"""Data scraping — 300 rapid GET requests, no user agent."""
import time,sys,os
sys.path.insert(0,os.path.dirname(__file__))
from config import hit,log,summary

ATTACK_IP="10.1.0.2"; TOTAL=300; DELAY=0.03

def run():
    log(f"Data Scraping — {TOTAL} requests from {ATTACK_IP}")
    log(f"Rate: ~{round(60/DELAY)} req/min | No user agent\n")
    results=[]
    for i in range(TOTAL):
        status,ms,_=hit("GET","/api/products",ip=ATTACK_IP,is_attack=True,user_agent="")
        results.append({"status":status,"ms":ms})
        if status in[403,429] and(i==0 or results[i-1]["status"] not in[403,429]):
            log(f"  [DETECTED] Request #{i+1}: {status}")
        if(i+1)%60==0:
            d=sum(1 for r in results if r["status"] in[403,429])
            log(f"  {i+1}/{TOTAL} | Detected: {d}")
        time.sleep(DELAY)
    s=summary("Data Scraping",results)
    dr=round(sum(1 for r in results if r["status"] in[403,429])/TOTAL*100,1)
    print(f"  DR: {dr}%  Target ≥85%  {'✅' if dr>=85 else '❌'}\n")
    return s

if __name__=="__main__": run()
