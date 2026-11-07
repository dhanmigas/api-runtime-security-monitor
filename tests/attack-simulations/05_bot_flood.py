"""Distributed bot flood — 50 IPs × 10 requests. Tests Layer 4."""
import time,random,threading,sys,os
sys.path.insert(0,os.path.dirname(__file__))
from config import hit,log,summary

NUM_IPS=50; REQ_PER_IP=10; TOTAL=NUM_IPS*REQ_PER_IP; CONCURRENCY=30
SUBNETS=["10.2.0","10.2.1","10.2.2","10.3.0","10.3.1"]

def run():
    log(f"Bot Flood — {NUM_IPS} IPs × {REQ_PER_IP} req = {TOTAL} total")
    log(f"Each IP rate: {REQ_PER_IP} req — UNDER any per-IP threshold")
    log("Only Layer 4 swarm detection catches this\n")
    bot_ips=[f"{random.choice(SUBNETS)}.{i+1}" for i in range(NUM_IPS)]
    results=[]; lock=threading.Lock()

    def bot(ip):
        for _ in range(REQ_PER_IP):
            status,ms,_=hit("GET","/api/products",ip=ip,is_attack=True,user_agent="")
            with lock: results.append({"status":status,"ms":ms,"ip":ip})
            time.sleep(random.uniform(0.05,0.15))

    sent=0; batch=0
    while sent<NUM_IPS:
        chunk=bot_ips[sent:sent+CONCURRENCY]
        threads=[threading.Thread(target=bot,args=(ip,)) for ip in chunk]
        batch+=1; log(f"  Batch {batch}: {len(chunk)} bots")
        for t in threads: t.start()
        for t in threads: t.join()
        sent+=CONCURRENCY
        with lock:
            d=sum(1 for r in results if r["status"] in[403,429])
            log(f"  After batch {batch}: {len(results)} sent, {d} detected")
        time.sleep(0.5)

    s=summary("Distributed Bot Flood",results)
    tp=sum(1 for r in results if r["status"] in[403,429])
    dr=round(tp/TOTAL*100,1)
    print(f"  DR: {dr}%  Target ≥85%  {'✅' if dr>=85 else '⚠ Check L4'}")
    print(f"  Key: each IP sent only {REQ_PER_IP} req — below per-IP threshold\n")
    return s

if __name__=="__main__": run()
