#!/usr/bin/env python3
"""Local Cloudflare DNS rotation panel. Python standard library only."""
import base64
import concurrent.futures
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get('DATA_DIR', ROOT / 'data'))
DB = DATA / 'panel.db'
LOCK = threading.RLock()
class TaskGate:
    """Per-group reservations plus an exclusive gate for configuration changes."""
    def __init__(self):
        self.condition = threading.Condition()
        self.active = set()
        self.exclusive = False

    def acquire(self, blocking=True, timeout=-1):
        with self.condition:
            ready = lambda: not self.exclusive and not self.active
            if not blocking and not ready(): return False
            if not self.condition.wait_for(ready, None if timeout < 0 else timeout): return False
            self.exclusive = True
            return True

    def release(self):
        with self.condition:
            self.exclusive = False
            self.condition.notify_all()

    def locked(self):
        with self.condition: return self.exclusive or bool(self.active)

    def reserve(self, gid):
        with self.condition:
            if self.exclusive or gid in self.active or len(self.active) >= 32: return False
            self.active.add(gid)
            return True

    def finish(self, gid):
        with self.condition:
            self.active.discard(gid)
            self.condition.notify_all()

RUNNING = TaskGate()
PROBE_LIMIT = threading.BoundedSemaphore(6)
HEALTH_LIMIT = threading.BoundedSemaphore(2)
STOP = threading.Event()

def connect():
    c = sqlite3.connect(DB, timeout=15)
    c.row_factory = sqlite3.Row
    return c

def init():
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    with connect() as c:
        c.executescript('''CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS groups (id TEXT PRIMARY KEY, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS templates (id TEXT PRIMARY KEY, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts REAL, domain TEXT, message TEXT);''')
        c.execute('INSERT OR IGNORE INTO settings VALUES (1, ?)', (json.dumps({'token':'', 'interval':3600, 'timeout':8, 'workers':3, 'health_interval':5, 'probe_url':'https://www.gstatic.com/generate_204'}),))
    os.chmod(DB, 0o600)
    migrate_failed_pools()

def settings():
    with connect() as c:
        s = json.loads(c.execute('SELECT data FROM settings WHERE id=1').fetchone()[0])
        s.setdefault('health_interval', 5)
        return s

def groups():
    with connect() as c:
        return [json.loads(r[0]) for r in c.execute('SELECT data FROM groups ORDER BY rowid')]

def templates():
    with connect() as c:
        return [json.loads(r[0]) for r in c.execute('SELECT data FROM templates ORDER BY rowid')]

def save_template(d):
    name=str(d.get('name','')).strip()
    if not 1<=len(name)<=80: raise ValueError('模板名称需为 1–80 个字符')
    node=str(d.get('node','')).strip();parsed,_=parse_node(node)
    with LOCK:
        saved=templates();tid=d.get('id') or uuid.uuid4().hex
        if d.get('id') and not any(t['id']==tid for t in saved): raise ValueError('模板不存在，请刷新后重试')
        if any(t['name']==name and t['id']!=tid for t in saved): raise ValueError('模板名称已存在')
        v={'id':tid,'name':name,'node':node,'port':parsed.port or 443}
        with connect() as c:
            c.execute('INSERT INTO templates(id,data) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data',(tid,json.dumps(v)))
        return v

def template_node(tid):
    if not tid: return ''
    saved=next((t for t in templates() if t['id']==tid),None)
    if not saved: raise ValueError('所选 VLESS 模板已删除，请重新选择')
    return saved['node']

def put(g):
    with LOCK, connect() as c:
        c.execute('INSERT INTO groups(id,data) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data', (g['id'], json.dumps(g)))

def put_runtime(g):
    """Retain IPs appended while this task was probing its earlier snapshot."""
    with LOCK:
        with connect() as c:
            row=c.execute('SELECT data FROM groups WHERE id=?',(g['id'],)).fetchone()
        if row:
            latest=json.loads(row[0])
            added=[ip for ip in latest['ips'] if ip not in g['ips']]
            if added:
                g['ips']+=added
                g['next_run']=min(g.get('next_run',time.time()),latest.get('next_run',time.time()))
        put(g)

def import_port_groups(d):
    # The batch may only append compatible IPs or create independent groups.
    # Network probes never hold this lock; validation + both writes are atomic.
    with LOCK:
        prepared=prepare_port_groups(d,groups())
        with connect() as c:
            for g in prepared:
                c.execute('INSERT INTO groups(id,data) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data',(g['id'],json.dumps(g)))
    return [{'domain':g['domain'],'port':g['port'],'count':len(g['ips'])} for g in prepared]

def event(domain, message):
    with connect() as c:
        c.execute('INSERT INTO events(ts,domain,message) VALUES(?,?,?)', (time.time(), domain, message))
        c.execute('DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 500)')

def parse_node(uri):
    p = urllib.parse.urlsplit(uri)
    if p.scheme != 'vless' or not p.hostname or not p.username:
        raise ValueError('请输入有效的 vless:// 节点')
    uuid.UUID(p.username)
    port = p.port or 443
    if not 1 <= port <= 65535:
        raise ValueError('端口无效')
    q = dict(urllib.parse.parse_qsl(p.query, keep_blank_values=True))
    if q.get('type','tcp') not in ('ws','tcp') or q.get('security','none') not in ('tls','none'):
        raise ValueError('当前支持 VLESS TCP / WS，可选 TLS；暂不支持 Reality / XHTTP / gRPC')
    if q.get('encryption','none') != 'none' or q.get('flow','') not in ('','xtls-rprx-vision'):
        raise ValueError('不支持该 encryption 或 flow')
    allowed = {'encryption','security','sni','type','host','path','flow','fp','alpn'}
    if set(q) - allowed:
        raise ValueError('存在暂不支持的参数：' + ', '.join(sorted(set(q)-allowed)))
    return p, q

def rewritten(uri, domain):
    p, _ = parse_node(uri)
    # Preserve the original query, including SNI, Host and percent encoding.
    return urllib.parse.urlunsplit((p.scheme, p.netloc.rsplit('@',1)[0]+'@'+domain+':'+str(p.port or 443), p.path, p.query, p.fragment))

def outbound(uri, ip):
    p, q = parse_node(uri)
    o = {'type':'vless','tag':'node','server':ip,'server_port':p.port or 443,'uuid':p.username}
    if q.get('flow'): o['flow'] = q['flow']
    if q.get('security') == 'tls':
        o['tls'] = {'enabled':True,'server_name':q.get('sni') or p.hostname}
        if q.get('fp'): o['tls']['utls'] = {'enabled':True,'fingerprint':q['fp']}
        if q.get('alpn'): o['tls']['alpn'] = q['alpn'].split(',')
    if q.get('type') == 'ws':
        o['transport'] = {'type':'ws','path':q.get('path','/'),'headers':{'Host':q.get('host') or q.get('sni') or p.hostname}}
    return o

def probe(g, ip, s):
    # Confirm transient failures before quarantining an address.
    for attempt in range(3):
        with (HEALTH_LIMIT if g.get('_health_probe') else PROBE_LIMIT):
            result = _probe(g, ip, s)
        result['attempts'] = attempt + 1
        if result['ok'] or result.get('environment_error'): return result
    return result

class ProbeEnvironmentError(RuntimeError):
    pass

def _probe(g, ip, s):
    started = time.monotonic()
    result = {'ip':ip,'ok':False,'mode':g['mode'],'checked':time.time()}
    try:
        p, q = parse_node(g['node'])
        if g['mode'] == 'proxy':
            binary = shutil.which('sing-box')
            if not binary or not shutil.which('curl'): raise ProbeEnvironmentError('完整测活需要 sing-box 和 curl')
            with socket.socket() as sock:
                sock.bind(('127.0.0.1',0)); port = sock.getsockname()[1]
            cfg = {'log':{'disabled':True}, 'inbounds':[{'type':'http','listen':'127.0.0.1','listen_port':port}], 'outbounds':[outbound(g['node'],ip)], 'route':{'final':'node'}}
            with tempfile.TemporaryDirectory(prefix='ddns-probe-') as td:
                path = Path(td)/'config.json'; path.write_text(json.dumps(cfg)); path.chmod(0o600)
                proc = subprocess.Popen([binary,'run','-c',str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    deadline = time.monotonic()+3
                    while True:
                        if proc.poll() is not None: raise ProbeEnvironmentError('sing-box 启动失败，请检查版本和节点参数')
                        try:
                            with socket.create_connection(('127.0.0.1',port),timeout=.2): break
                        except OSError:
                            if time.monotonic() >= deadline: raise ProbeEnvironmentError('sing-box 启动超时')
                            time.sleep(.05)
                    # Disable environment proxy bypass; the request must traverse this node.
                    targets = list(dict.fromkeys([s['probe_url'], 'https://cp.cloudflare.com/generate_204']))
                    responses = []
                    for target in targets:
                        r = subprocess.run(['curl','--silent','--output',os.devnull,'--write-out','%{http_code}', '--noproxy','','--proxy',f'http://127.0.0.1:{port}','--connect-timeout',str(s['timeout']),'--max-time',str(s['timeout']),target], capture_output=True, text=True, timeout=s['timeout']+2)
                        if not r.returncode and r.stdout.isdigit() and 200 <= int(r.stdout) < 300: break
                        responses.append(r.stdout[:3])
                    else:
                        if any(code.isdigit() and int(code) >= 400 for code in responses):
                            raise ProbeEnvironmentError('检测目标返回异常 HTTP，暂停淘汰 IP')
                        raise RuntimeError('代理请求失败 / 超时（主备目标均失败）')
                finally:
                    proc.terminate()
                    try: proc.wait(timeout=2)
                    except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        else:
            with socket.create_connection((ip,p.port or 443),timeout=s['timeout']) as sock:
                if g['mode'] == 'tls':
                    if q.get('security') != 'tls': raise ValueError('此节点未启用 TLS')
                    with ssl.create_default_context().wrap_socket(sock,server_hostname=q.get('sni') or p.hostname): pass
        result.update(ok=True, ms=round((time.monotonic()-started)*1000))
    except (ProbeEnvironmentError, FileNotFoundError, PermissionError) as e:
        result.update(environment_error=True, error=str(e)[:180])
    except Exception as e:
        result['error'] = str(e)[:180]
    return result

class Cloudflare:
    def __init__(self, token): self.token = token
    def call(self, method, path, data=None):
        req = urllib.request.Request('https://api.cloudflare.com/client/v4'+path, data=json.dumps(data).encode() if data is not None else None, headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json'}, method=method)
        try:
            with urllib.request.urlopen(req,timeout=20) as r: body=json.load(r)
        except urllib.error.HTTPError as e:
            raise RuntimeError('Cloudflare HTTP '+str(e.code)+'，请检查 Token、Zone ID 和权限') from None
        if not body.get('success'): raise RuntimeError('Cloudflare 拒绝请求，请检查 DNS 权限和记录冲突')
        return body
    def update(self, zone, domain, ip):
        typ = 'A' if ipaddress.ip_address(ip).version == 4 else 'AAAA'
        # Refuse ambiguous multi-address records instead of deleting user records.
        path = '/zones/'+zone+'/dns_records'
        records = self.call('GET',path+'?'+urllib.parse.urlencode({'name':domain,'per_page':100}))
        rs=records['result']
        if records.get('result_info',{}).get('total_count',len(rs)) > 100: raise RuntimeError('同名记录过多，请先整理')
        if any(r['type'] in ('CNAME','A','AAAA') and r['type'] != typ for r in rs):
            raise RuntimeError('存在同名 CNAME 或另一地址族记录，请先整理；本程序不会删除现有记录')
        matches=[r for r in rs if r['type']==typ]
        if len(matches)>1: raise RuntimeError('存在多条同名 DNS 记录，请先保留一条')
        payload={'type':typ,'name':domain,'content':ip,'ttl':60,'proxied':False}
        if matches:
            if matches[0]['content']==ip and not matches[0].get('proxied') and matches[0].get('ttl')==60: return
            self.call('PATCH',path+'/'+matches[0]['id'],payload)
        else: self.call('POST',path,payload)

    def delete_domain(self, zone, domain):
        path='/zones/'+zone+'/dns_records'
        response=self.call('GET',path+'?'+urllib.parse.urlencode({'name':domain,'per_page':100}))
        records=response['result']
        if response.get('result_info',{}).get('total_count',len(records))>100:
            raise RuntimeError('同名记录超过 100 条，请先在 Cloudflare 整理')
        matches=[r for r in records if r.get('name','').lower().rstrip('.')==domain.lower().rstrip('.') and r['type'] in ('A','AAAA')]
        for record in matches:
            self.call('DELETE',path+'/'+record['id'])
        return len(matches)

def delete_group(gid):
    g=next((g for g in groups() if g['id']==gid),None)
    if not g: raise ValueError('子域名不存在或已删除')
    token=settings()['token']
    if not token: raise ValueError('请先配置 Cloudflare Token，删除时需要同步清理 DNS')
    try:
        count=Cloudflare(token).delete_domain(g['zone'],g['domain'])
    except Exception as e:
        event(g['domain'],'删除失败，已保留本地配置：'+str(e)[:180])
        raise RuntimeError('Cloudflare DNS 删除失败，本地配置已保留：'+str(e)[:150]) from None
    with connect() as c: c.execute('DELETE FROM groups WHERE id=?',(gid,))
    event(g['domain'],'域名已删除，同时清理 '+str(count)+' 条 Cloudflare 地址记录')
    return count

RECOVERY_INTERVAL = 86400
RECOVERY_DELAYS = (300, 1800, 7200, 86400)

def migrate_failed_pools():
    for g in groups():
        if g.get('pool_version')==1: continue
        failed=g.setdefault('failed_ips',{})
        results={r['ip']:r for r in g.get('results',[]) if r.get('ip') in g['ips']}
        health=g.get('current_health',{})
        current=g.get('current')
        if current in g['ips'] and 'ok' in health:
            if health.get('checked',0)>=results.get(current,{}).get('checked',0): results[current]=health
        now=time.time()
        for ip,r in results.items():
            if not r['ok'] and ip not in failed:
                failed[ip]={'since':now,'checked':r.get('checked',now),
                            'next_retry':now+RECOVERY_INTERVAL,'error':r.get('error','连接失败')}
        if current in failed: g['next_run']=now
        g['pool_version']=1
        put(g)

def active_ips(g):
    failed=g.get('failed_ips',{})
    return [ip for ip in g['ips'] if ip not in failed]

def record_probe(g, result, ip=None):
    ip=ip or result['ip']
    result=dict(result,ip=ip)
    g['results']=[r for r in g.get('results',[]) if r['ip']!=ip]+[result]
    if ip==g.get('current'): g['current_health']=result
    failed=g.setdefault('failed_ips',{})
    if result.get('environment_error'):
        if ip in failed: failed[ip]['next_retry']=time.time()+300
        return
    if not result['ok']:
        now=time.time()
        old=failed.get(ip,{})
        level=min(old.get('retry_level', -1)+1,len(RECOVERY_DELAYS)-1)
        failed[ip]={'since':old.get('since',now),'checked':now,'retry_level':level,
                    'next_retry':now+RECOVERY_DELAYS[level],'error':result.get('error','连接失败')}
        if not old: event(g['domain'],'IP 移入失效池 → '+ip)

def recovery_due(g):
    return any(v.get('next_retry',0)<=time.time() for v in g.get('failed_ips',{}).values())

def recover_failed(g, s, force=False):
    # Small batches keep daily retries from monopolizing health-check scheduling.
    due=[ip for ip,v in g.get('failed_ips',{}).items()
         if ip in g['ips'] and (force or v.get('next_retry',0)<=time.time())]
    if not force: due=due[:s['workers']]
    if not due: return
    with concurrent.futures.ThreadPoolExecutor(max_workers=s['workers']) as pool:
        results=list(pool.map(lambda ip:probe(g,ip,s),due))
    for ip,result in zip(due,results):
        record_probe(g,result,ip)
        if result['ok']:
            del g['failed_ips'][ip]
            event(g['domain'],'复活检测通过，已返回原 IP 池 → '+ip)
            if g.get('enabled') and (not g.get('current') or g['current'] in g['failed_ips'] or g['current']==ip):
                g['next_run']=time.time()
        elif not result.get('environment_error'): event(g['domain'],'复活检测仍失败，已延长重试间隔 → '+ip)
    put_runtime(g)

def scheduled_due(g):
    return recovery_due(g) or (g['enabled'] and
        (g.get('next_run',0)<=time.time() or
         (g.get('current') in active_ips(g) and g.get('next_check',0)<=time.time())))

def clean_failed_pool(g):
    g['failed_ips']={ip:v for ip,v in g.get('failed_ips',{}).items() if ip in g['ips']}

def rotate(g, s, write):
    results=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=s['workers']) as pool:
        candidates=active_ips(g)
        results=list(pool.map(lambda ip:probe(g,ip,s),candidates))
    for ip,result in zip(candidates,results): record_probe(g,result,ip)
    g['checked']=time.time()
    good={r['ip'] for r in results if r['ok']}
    environment_errors=[r.get('error','检测环境异常') for r in results if r.get('environment_error')]
    if environment_errors: g['error']=environment_errors[0]
    if not write:
        put_runtime(g); event(g['domain'],'测活完成：'+str(len(good))+'/'+str(len(results))); return
    try:
        if not good: raise RuntimeError(environment_errors[0] if environment_errors else '正常池无可用 IP，保留原 DNS；失效池按递增间隔复活检测')
        best=min((r for r in results if r['ok']),
                 key=lambda r:(r.get('ms',float('inf')),r['ip']!=g.get('current')))
        chosen=best['ip']
        if not s['token']: raise RuntimeError('尚未配置 Cloudflare API Token')
        Cloudflare(s['token']).update(g['zone'],g['domain'],chosen)
        g.update(current=chosen, rotated=time.time(), error='', current_health=next(r for r in results if r['ip']==chosen))
        event(g['domain'],'延迟优选 → '+chosen+' / '+str(best.get('ms','—'))+' ms')
    except Exception as e:
        g['error']=str(e)[:200]; event(g['domain'],g['error'])
    g['next_run']=time.time()+s['interval'] if not g.get('error') else time.time()+min(30,s['interval'])
    g['next_check']=time.time()+s['health_interval']
    if not active_ips(g):
        g['next_run']=min((v['next_retry'] for v in g.get('failed_ips',{}).values()),default=time.time()+RECOVERY_INTERVAL)
    put_runtime(g)

def switch_ip(g, ip, s):
    """Check exactly the selected candidate; commit local state only after DNS succeeds."""
    try:
        result=probe(g,ip,s)
        record_probe(g,result,ip)
        if not result['ok']:
            raise RuntimeError('所选 IP 测活失败，未切换：'+result.get('error','连接失败'))
        Cloudflare(s['token']).update(g['zone'],g['domain'],ip)
        now=time.time()
        g.update(current=ip,rotated=now,current_health=result,error='',
                 next_run=now+s['interval'],next_check=now+s['health_interval'])
        g['manual_switch']={'status':'success','ip':ip,'ts':now}
        event(g['domain'],'手动切换成功 → '+ip)
    except Exception as e:
        message=str(e)[:200]
        g['manual_switch']={'status':'failed','ip':ip,'ts':time.time(),'error':message}
        event(g['domain'],'手动切换失败：'+message)
    put_runtime(g)

def start_switch(gid, ip):
    if not RUNNING.reserve(gid): return False
    try:
        g=next((g for g in groups() if g['id']==gid),None)
        if not g: raise ValueError('子域名不存在')
        ip=str(ipaddress.ip_address(ip))
        if ip not in active_ips(g): raise ValueError('请选择正常 IP 池中的地址；失效 IP 等待复活检测')
        s=settings()
        if not s['token']: raise ValueError('请先配置 Cloudflare API Token')
        g['manual_switch']={'status':'running','ip':ip,'ts':time.time()}
        put_runtime(g)
        def work():
            try: switch_ip(g,ip,s)
            finally: RUNNING.finish(gid)
        threading.Thread(target=work,daemon=True).start()
    except Exception:
        RUNNING.finish(gid)
        raise
    return True

def run(ids=None, write=True, scheduled=False, recovery_only=False):
    s=settings()
    candidates=[g for g in groups() if (ids is None or g['id'] in ids)
                and (not scheduled or scheduled_due(g))]
    # Dispatch current-node checks before full-pool scans.
    candidates.sort(key=lambda g: not (g.get('current') and g.get('next_check',0)<=time.time()))
    started=False
    def process(g):
        try:
            if STOP.is_set(): return
            if recovery_only:
                recover_failed(g,s,force=True)
                return
            if scheduled:
                if g['enabled'] and g.get('current') in active_ips(g) and g.get('next_check',0)<=time.time():
                    result=probe(dict(g,_health_probe=True),g['current'],s)
                    record_probe(g,result,g['current'])
                    g['next_check']=time.time()+s['health_interval']
                    put_runtime(g)
                    if result.get('environment_error'):
                        g['error']=result.get('error','检测环境异常')
                        g['next_run']=max(g.get('next_run',0),time.time()+30)
                        put_runtime(g)
                        return
                    if not result['ok']:
                        event(g['domain'],'当前节点连续检测失败，开始故障切换')
                        rotate(g,s,write)
                        return
                if g['enabled'] and g.get('next_run',0)<=time.time():
                    rotate(g,s,write)
                recover_failed(g,s)
                return
            rotate(g,s,write)
        except Exception as e:
            g['next_run']=time.time()+30
            g['next_check']=time.time()+s['health_interval']
            g['error']='任务失败：'+str(e)[:180]
            put_runtime(g)
            event(g['domain'],g['error'])
        finally: RUNNING.finish(g['id'])
    for g in candidates:
        if not RUNNING.reserve(g['id']): continue
        try:
            threading.Thread(target=process,args=(g,),daemon=True).start()
            started=True
        except Exception:
            RUNNING.finish(g['id'])
            raise
    return started

def active_tasks():
    with RUNNING.condition: return sorted(RUNNING.active)

def scheduler():
    while not STOP.wait(1):
        if any(scheduled_due(g) for g in groups()): run(scheduled=True)

DEFAULT_DOMAIN = 'example.com'
PORT_SUFFIX = {443:'1', 8443:'2'}

def domain_for_port(domain, port):
    domain=str(domain).strip().lower().rstrip('.')
    if domain and '.' not in domain: domain+='.'+DEFAULT_DOMAIN
    if port in PORT_SUFFIX and '.' in domain:
        label, rest=domain.split('.',1)
        label=re.sub(r'-(?:1|2)$','',label)
        domain=label+'-'+PORT_SUFFIX[port]+'.'+rest
    return domain

def extract_ips(text):
    if not isinstance(text,str) or not text.strip(): raise ValueError('请先粘贴节点或 IP＋端口')
    tokens=text.split()
    entries=[]; i=0
    while i<len(tokens):
        token=tokens[i]
        if i+1<len(tokens) and tokens[i+1].isdigit():
            try:
                ipaddress.ip_address(token.strip('[]'))
                entries.append((token,tokens[i+1])); i+=2; continue
            except ValueError: pass
        entries.append((token,None)); i+=1
    ips=[]; seen=set(); domains=[]; invalid=0; duplicates=0; other=0
    buckets={str(port):{'port':port,'ips':[],'duplicates':0,'node':''} for port in PORT_SUFFIX}
    for entry, separated_port in entries:
        try:
            template=''
            if entry.lower().startswith('vless://'):
                node=urllib.parse.urlsplit(entry)
                if not node.hostname or not node.username: raise ValueError('invalid')
                port=node.port if node.port is not None else 443
                try: ip=str(ipaddress.ip_address(node.hostname))
                except ValueError:
                    domains.append(node.hostname); continue
                template=entry
            elif separated_port is not None:
                ip=str(ipaddress.ip_address(entry.strip('[]'))); port=int(separated_port)
            else:
                # IPv6 with a colon-separated port must use [IPv6]:port.
                match=re.fullmatch(r'(\[[^\]]+\]|[^:]+):([0-9]+)',entry.replace('：',':'))
                if not match: raise ValueError('需要 IP:端口 或 IP 空格 端口')
                ip=str(ipaddress.ip_address(match[1].strip('[]'))); port=int(match[2])
            if not 1<=port<=65535: raise ValueError('invalid port')
            if port not in PORT_SUFFIX: other+=1; continue
            bucket=buckets[str(port)]
            if template and not bucket['node']: bucket['node']=template
            if ip in bucket['ips']: bucket['duplicates']+=1
            else: bucket['ips'].append(ip)
            if ip in seen: duplicates+=1
            else: seen.add(ip); ips.append(ip)
        except ValueError: invalid+=1
    return {'ips':ips,'total':len(entries),'duplicates':duplicates,
            'domain_count':len(domains),'domains':list(dict.fromkeys(domains)),
            'invalid':invalid,'other_port_count':other,'port_groups':buckets}

def node_for_port(uri, port):
    p,_=parse_node(uri)
    host='['+p.hostname+']' if ':' in p.hostname else p.hostname
    return urllib.parse.urlunsplit((p.scheme,p.netloc.rsplit('@',1)[0]+'@'+host+':'+str(port),p.path,p.query,p.fragment))

def prepare_port_groups(d, existing):
    extracted=extract_ips(d.get('text'))
    prepared=[]
    for bucket in extracted['port_groups'].values():
        if not bucket['ips']: continue
        template=template_node(d.get('template_'+str(bucket['port']))) or str(d.get('node','')).strip() or bucket['node']
        if not template: raise ValueError(str(bucket['port'])+' 端口的纯 IP 导入需要一条 VLESS 模板')
        values=dict(domain=d.get('domain',''),zone=d.get('zone',''),node=node_for_port(template,bucket['port']),
                    ips=bucket['ips'],mode=d.get('mode','proxy'),enabled=bool(d.get('enabled',False)))
        v=validate_group(values)
        # Explicitly append only to the same port/template; never overwrite other credentials.
        match=next((g for g in existing if g['domain']==v['domain']),None)
        if match:
            if match['zone']!=v['zone']: raise ValueError(v['domain']+' 的 Zone ID 与现有配置不同')
            def signature(uri):
                return outbound(uri,'0.0.0.0')
            if signature(match['node'])!=signature(v['node']):
                raise ValueError(v['domain']+' 已存在且节点参数不同，请换一个基础名称或编辑现有组')
            v=validate_group(dict(v,ips=match['ips']+v['ips']))
            g=dict(match)
            # Existing enabled/paused state remains as configured.
            v['enabled']=match['enabled']
        else: g={'id':uuid.uuid4().hex}
        g.update(v,next_run=time.time(),next_check=time.time())
        clean_failed_pool(g)
        prepared.append(g)
    if not prepared: raise ValueError('没有可导入的 443 / 8443 IP 节点')
    return prepared

def validate_group(d):
    node=str(d.get('node','')).strip() or template_node(d.get('template_id')); parsed,_=parse_node(node)
    port=parsed.port or 443
    domain=domain_for_port(d.get('domain',''),port)
    if len(domain)>253 or '.' not in domain or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',v) for v in domain.split('.')): raise ValueError('请输入完整子域名')
    zone=str(d.get('zone','')).strip()
    if not re.fullmatch('[a-fA-F0-9]{32}',zone): raise ValueError('Zone ID 应为 32 位十六进制值')
    raw=d.get('ips',[])
    if isinstance(raw,str): raw=re.split(r'[\s,;]+',raw.strip())
    if not isinstance(raw,list) or not all(isinstance(v,str) for v in raw): raise ValueError('IP 池格式无效')
    ips=list(dict.fromkeys(str(ipaddress.ip_address(v.strip())) for v in raw if v.strip()))
    if not 1<=len(ips)<=512: raise ValueError('去重后每组支持 1–512 个 IP')
    if len({ipaddress.ip_address(v).version for v in ips})!=1: raise ValueError('每组使用同一种地址族的 IP')
    mode=d.get('mode','proxy')
    if mode not in ('proxy','tcp','tls'): raise ValueError('测活模式无效')
    return dict(domain=domain,zone=zone,node=node,port=port,ips=ips,mode=mode,enabled=bool(d.get('enabled',False)))

class Handler(BaseHTTPRequestHandler):
    server_version='DDNSPanel'
    def log_message(self,*args): pass
    def reply(self,code,body,ctype='application/json; charset=utf-8'):
        if not isinstance(body,bytes): body=json.dumps(body,ensure_ascii=False).encode()
        self.send_response(code); self.send_header('Content-Type',ctype); self.send_header('Content-Length',str(len(body))); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('X-Frame-Options','DENY'); self.end_headers(); self.wfile.write(body)
    def auth(self):
        if not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+self.server.password):
            self.reply(401,{'error':'管理密码错误'}); return False
        return True
    def do_GET(self):
        path=urllib.parse.urlsplit(self.path).path
        if path in ('/','/app.js','/style.css'):
            name={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}[path]
            self.reply(200,(ROOT/'static'/name).read_bytes(),{'/':'text/html; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8'}[path]); return
        if not self.auth(): return
        if path=='/api/state':
            s=settings(); s['token_set']=bool(s.pop('token'))
            gs=groups()
            for g in gs:
                g['link']=rewritten(g['node'],g['domain'])
                g['port']=parse_node(g['node'])[0].port or 443
                g['active_ips']=active_ips(g)
                g.setdefault('failed_ips',{})
            with connect() as c: events=[dict(r) for r in c.execute('SELECT ts,domain,message FROM events ORDER BY id DESC LIMIT 80')]
            self.reply(200,{'settings':s,'groups':gs,'templates':templates(),'events':events,'busy':RUNNING.locked(),'active_tasks':active_tasks(),'sing_box':bool(shutil.which('sing-box')),'curl':bool(shutil.which('curl'))})
        else: self.reply(404,{'error':'不存在'})
    def do_POST(self):
        if not self.auth(): return
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<=1024*1024: raise ValueError('请求大小不正确')
            d=json.loads(self.rfile.read(length)); path=urllib.parse.urlsplit(self.path).path
            if path=='/api/extract':
                self.reply(200,extract_ips(d.get('text'))); return
            elif path=='/api/template':
                self.reply(200,{'ok':True,'template':save_template(d)}); return
            elif path=='/api/template-delete':
                if not isinstance(d.get('id'),str): raise ValueError('模板 ID 无效')
                with LOCK, connect() as c: c.execute('DELETE FROM templates WHERE id=?',(d['id'],))
                self.reply(200,{'ok':True}); return
            elif path=='/api/import-ports':
                self.reply(200,{'ok':True,'groups':import_port_groups(d)}); return
            elif path=='/api/recover':
                ids=d.get('ids')
                if not isinstance(ids,list) or not all(isinstance(v,str) for v in ids): raise ValueError('ids 无效')
                if not run(ids,write=False,recovery_only=True): self.reply(409,{'error':'所选域名任务运行中，请稍后重试'}); return
            elif path=='/api/switch':
                if not isinstance(d.get('id'),str) or not isinstance(d.get('ip'),str): raise ValueError('请选择子域名和 IP')
                if not start_switch(d['id'],d['ip']): self.reply(409,{'error':'任务正在运行，请稍后重试'}); return
            elif path in ('/api/probe','/api/rotate'):
                ids=d.get('ids')
                if ids is not None and (not isinstance(ids,list) or not all(isinstance(v,str) for v in ids)): raise ValueError('ids 无效')
                if not run(ids,write=path.endswith('rotate')): self.reply(409,{'error':'任务正在运行，请稍后'}); return
            elif path in ('/api/group','/api/delete','/api/settings'):
                # Serialize configuration writes against the entire probe/DNS task.
                if not RUNNING.acquire(blocking=False): self.reply(409,{'error':'任务运行中，完成后可修改配置'}); return
                LOCK.acquire()
                try:
                    if path=='/api/group':
                        v=validate_group(d); gid=d.get('id') or uuid.uuid4().hex
                        existing=next((g for g in groups() if g['id']==gid),{})
                        if any(g['domain']==v['domain'] and g['id']!=gid for g in groups()): raise ValueError('该子域名已经存在')
                        if existing and existing['domain']!=v['domain']:
                            existing={k:existing[k] for k in ('failed_ips',) if k in existing}
                        existing.update(v,id=gid,next_run=time.time(),next_check=time.time())
                        clean_failed_pool(existing)
                        put(existing)
                    elif path=='/api/delete':
                        delete_group(d['id'])
                    else:
                        s=settings()
                        for k,lo,hi in [('interval',60,604800),('timeout',2,60),('workers',1,8),('health_interval',2,3600)]:
                            value=int(d.get(k,s[k]))
                            if not lo<=value<=hi: raise ValueError(k+' 超出范围')
                            s[k]=value
                        url=d.get('probe_url',s['probe_url'])
                        if urllib.parse.urlsplit(url).scheme!='https' or not urllib.parse.urlsplit(url).hostname: raise ValueError('测活目标需要 HTTPS URL')
                        s['probe_url']=url
                        if d.get('token','').strip(): s['token']=d['token'].strip()
                        with connect() as c: c.execute('UPDATE settings SET data=? WHERE id=1',(json.dumps(s),))
                        for g in groups(): g['next_run']=time.time()+s['interval']; put(g)
                finally:
                    LOCK.release()
                    RUNNING.release()
            else: self.reply(404,{'error':'不存在'}); return
            self.reply(200,{'ok':True})
        except (ValueError,KeyError,TypeError) as e: self.reply(400,{'error':str(e)[:200]})
        except RuntimeError as e: self.reply(502,{'error':str(e)[:250]})
        except Exception: self.reply(500,{'error':'操作失败，请检查配置和本地存储'})

def main():
    init()
    password=os.environ.get('ADMIN_PASSWORD','')
    if not password:
        p=DATA/'admin-password'
        if not p.exists():
            fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as f: f.write(secrets.token_urlsafe(24))
        password=p.read_text().strip()
    if len(password)<12: raise SystemExit('ADMIN_PASSWORD 至少 12 个字符')
    host=os.environ.get('BIND','127.0.0.1'); port=int(os.environ.get('PORT','8787'))
    server=ThreadingHTTPServer((host,port),Handler); server.password=password
    threading.Thread(target=scheduler,daemon=True).start()
    print(f'DDNS Panel listening on {host}:{port}. Password: ADMIN_PASSWORD or {DATA}/admin-password',flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: STOP.set(); server.server_close()

if __name__=='__main__': main()
