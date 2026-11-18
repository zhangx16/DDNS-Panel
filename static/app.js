const expandedPools = new Set();
const $=s=>document.querySelector(s);let password=sessionStorage.getItem('ddns-password')||'',state=null,toastTimer;let extractedIps=[],extractedData=null,extractedText='';
function toast(t){$('#toast').textContent=t;$('#toast').style.display='block';clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('#toast').style.display='none',5000)}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function api(path,data){const r=await fetch('/api/'+path,{method:data===undefined?'GET':'POST',headers:{Authorization:'Bearer '+password,'Content-Type':'application/json'},body:data===undefined?undefined:JSON.stringify(data)});const d=await r.json();if(r.status===401){$('#login').classList.remove('hidden');throw Error(d.error)}if(!r.ok)throw Error(d.error||'请求失败');return d}
function dt(t){return t?new Date(t*1000).toLocaleString('zh-CN',{hour12:false}):'尚未执行'}
function activeIps(g){return g.active_ips||g.ips.filter(ip=>!g.failed_ips?.[ip])}
function groupMarkup(g){const health=g.current_health||g.results?.find(r=>r.ip===g.current);const status=!g.enabled?'已暂停':health?(health.ok?'当前可用':'检测失败'):'等待检测';return `<article class="node" data-group-id="${esc(g.id)}"><div class="node-top"><div><button type="button" class="domain domain-copy" data-act="copy-domain" data-id="${esc(g.id)}" title="点击复制域名" aria-label="复制域名 ${esc(g.domain)}">${esc(g.domain)}</button><span class="badge">${esc(g.port||443)} 端口</span><span class="state ${health?(health.ok?'ok':'bad'):''}">${status}</span></div><div class="actions"><button data-act="probe" data-id="${esc(g.id)}">测活</button><button data-act="rotate" data-id="${esc(g.id)}">立即优选</button><button data-act="switch" data-id="${esc(g.id)}">手动切换 IP</button><button data-act="copy" data-id="${esc(g.id)}">复制节点</button><button data-act="edit" data-id="${esc(g.id)}">编辑</button><button data-act="delete" data-id="${esc(g.id)}">删除</button></div></div><div class="meta">当前解析：<b>${esc(g.current||'未同步')}</b> &nbsp; / &nbsp; ${esc({proxy:'完整代理测活',tls:'仅 TLS 握手',tcp:'仅 TCP 连通'}[g.mode])} &nbsp; / &nbsp; ${health?.ok?esc(health.ms)+' ms':''}<br>任务 ${state.active_tasks?.includes(g.id)?'执行中':'待命'} &nbsp; · &nbsp; 上次轮换 ${dt(g.rotated)} &nbsp; · &nbsp; 下次轮换 ${g.enabled?dt(g.next_run):'已暂停'} &nbsp; · &nbsp; 当前检测 ${dt(health?.checked)}</div><button class="pool-toggle" data-act="pool" data-id="${esc(g.id)}" aria-expanded="${expandedPools.has(g.id)}" aria-controls="pool-${esc(g.id)}">${expandedPools.has(g.id)?'▾ 收起':'▸ 展开'} 正常 IP 池 <span class="badge">${activeIps(g).length}</span></button><div id="pool-${esc(g.id)}" class="ips" ${expandedPools.has(g.id)?'':'hidden'}>${activeIps(g).map(ip=>{const r=g.results?.find(r=>r.ip===ip);return `<span title="${esc(r?.error||'')}" class="ip ${ip===g.current?'active':''}">${r?(r.ok?'● ':'× '):''}${esc(ip)}${r?.ok&&Number.isFinite(r.ms)?' · '+esc(r.ms)+' ms':''}</span>`}).join('')||'<span class="meta">正常池暂无 IP，等待分级复活检测。</span>'}</div><button class="pool-toggle failed-toggle" data-act="failed" data-id="${esc(g.id)}" aria-expanded="${expandedPools.has('failed:'+g.id)}" aria-controls="failed-${esc(g.id)}">${expandedPools.has('failed:'+g.id)?'▾ 收起':'▸ 展开'} 失效池 <span class="badge">${Object.keys(g.failed_ips||{}).length}</span></button><div class="failed-list" id="failed-${esc(g.id)}" ${expandedPools.has('failed:'+g.id)?'':'hidden'}>${Object.entries(g.failed_ips||{}).map(([ip,r])=>`<div class="failed-entry"><b>${esc(ip)}</b><span>${esc(r.error)}</span><small>移入 ${dt(r.since)} · 最近检测 ${dt(r.checked)}<br>下次复活检测 ${dt(r.next_retry)}</small></div>`).join('')||'<p>暂无失效 IP</p>'}</div>${g.manual_switch?`<p class="${g.manual_switch.status==='failed'?'error':'meta'}">${esc({running:'正在检测并切换 → ',success:'手动切换成功 → ',failed:'手动切换失败 → '}[g.manual_switch.status])}${esc(g.manual_switch.ip)}${g.manual_switch.error?'：'+esc(g.manual_switch.error):''}</p>`:''}${g.error?`<div class="error">${esc(g.error)}</div>`:''}${health&&!health.ok?`<div class="error">${esc(health.error)}</div>`:''}</article>`}
// Keep existing cards, controls and scroll containers mounted while updating status.
function patchNode(current,next){
 if(current.nodeType!==next.nodeType||current.nodeName!==next.nodeName){current.replaceWith(next.cloneNode(true));return}
 if(current.nodeType===Node.TEXT_NODE){if(current.nodeValue!==next.nodeValue)current.nodeValue=next.nodeValue;return}
 if(current.nodeType!==Node.ELEMENT_NODE)return;
 for(const attr of [...current.attributes])if(!next.hasAttribute(attr.name))current.removeAttribute(attr.name);
 for(const attr of [...next.attributes])if(current.getAttribute(attr.name)!==attr.value)current.setAttribute(attr.name,attr.value);
 const oldChildren=[...current.childNodes],newChildren=[...next.childNodes];
 for(let i=0;i<Math.max(oldChildren.length,newChildren.length);i++){
  if(!newChildren[i])oldChildren[i].remove();
  else if(!oldChildren[i])current.appendChild(newChildren[i].cloneNode(true));
  else patchNode(oldChildren[i],newChildren[i]);
 }
}
function renderGroups(){
 if(!state)return;
 const filter=$('#search').value.toLowerCase(),gs=state.groups.filter(g=>g.domain.includes(filter)||g.ips.some(ip=>ip.includes(filter)));
 const root=$('#groups'),ids=new Set(gs.map(g=>g.id)),cards=new Map([...root.querySelectorAll(':scope > article[data-group-id]')].map(el=>[el.dataset.groupId,el]));
 for(const child of [...root.children])if(!child.dataset.groupId||!ids.has(child.dataset.groupId))child.remove();
 let cursor=root.firstElementChild;
 for(const g of gs){
  let card=cards.get(g.id);const markup=groupMarkup(g);
  if(!card||card._markup!==markup){const template=document.createElement('template');template.innerHTML=markup;const next=template.content.firstElementChild;
   if(card)patchNode(card,next);else card=next;
   card._markup=markup;
  }
  if(card!==cursor)root.insertBefore(card,cursor);
  cursor=card.nextElementSibling;
 }
 if(!gs.length){const empty=document.createElement('div');empty.className='empty';empty.textContent='还没有匹配的子域名。添加子域名、节点和 IP 池，即可开始本机调度。';root.appendChild(empty)}
}
async function refresh(fill=false){try{state=await api('state');$('#login').classList.add('hidden');$('#count').textContent=state.groups.length;$('#badge').textContent=state.groups.length;$('#healthy').textContent=state.groups.filter(g=>(g.current_health||g.results?.find(r=>r.ip===g.current))?.ok).length;$('#timing').textContent=`${Math.round(state.settings.interval/60)} 分 / ${state.settings.health_interval} 秒`;$('#busy').textContent=state.busy?`${state.active_tasks?.length||0} 组执行中`:'待命';$('#engine').textContent=state.sing_box&&state.curl?'sing-box 完整测活就绪':'完整测活依赖未就绪';$('#engine-status').textContent=state.busy?'检测 / DNS 同步任务正在执行':'等待下一个调度周期';$('#token-state').textContent=state.settings.token_set?'已配置 Token，留空不会覆盖':'尚未配置 Token';if(fill)for(const[k,v]of Object.entries(state.settings)){const e=$('#settings-form').elements[k];if(e&&k!=='token')e.value=v}renderGroups();renderExtractTargets();renderTemplates();$('#logs').innerHTML=state.events.length?state.events.map(e=>`<div class="log"><time>${dt(e.ts)}</time><span>${esc(e.domain)}</span><span>${esc(e.message)}</span></div>`).join(''):'<p>暂无运行记录</p>'}catch(e){if(fill)toast(e.message)}}
$('#login-form').onsubmit=async e=>{e.preventDefault();password=$('#password').value;try{await api('state');sessionStorage.setItem('ddns-password',password);$('#login-error').textContent='';await refresh(true)}catch(e){$('#login-error').textContent=e.message}};
$('#logout').onclick=()=>{password='';sessionStorage.removeItem('ddns-password');$('#password').value='';$('#login').classList.remove('hidden')};
function edit(g){const f=$('#group-form');f.reset();f.elements.id.value=g?.id||'';if(g)for(const k of ['domain','zone','node','mode'])f.elements[k].value=g[k];if(g&&g.domain.endsWith('.example.com')&&g.domain.split('.').length===3)f.elements.domain.value=g.domain.slice(0,-'.example.com'.length);f.elements.ips.value=g?.ips.join('\n')||'';f.elements.enabled.checked=g?.enabled||false;$('#editor-title').textContent=g?'编辑子域名':'添加子域名';updateDomainPreview();$('#editor').showModal()}
$('#add').onclick=()=>edit();$('#close').onclick=()=>$('#editor').close();$('#search').oninput=renderGroups;
$('#group-form').onsubmit=async e=>{e.preventDefault();const f=e.target,d=Object.fromEntries(new FormData(f));d.enabled=f.elements.enabled.checked;try{await api('group',d);$('#editor').close();toast('子域名已保存，IP 池已自动去重');refresh()}catch(e){toast(e.message)}};
$('#settings-form').onsubmit=async e=>{e.preventDefault();const d=Object.fromEntries(new FormData(e.target));try{await api('settings',d);e.target.elements.token.value='';toast('设置已保存');refresh()}catch(e){toast(e.message)}};
async function action(kind,ids){try{await api(kind,ids?{ids}:{});toast(kind==='probe'?'测活任务已启动':'延迟优选任务已启动');refresh()}catch(e){toast(e.message)}}
$('#probe-all').onclick=()=>action('probe');$('#rotate-all').onclick=()=>{if(confirm('检测各池并选择延迟最低的可用 IP，更新所有子域名 DNS？包含已暂停的组。'))action('rotate')};
$('#groups').onclick=async e=>{const b=e.target.closest('button[data-act]');if(!b)return;const g=state.groups.find(g=>g.id===b.dataset.id);if(!g)return;const a=b.dataset.act;if(a==='copy-domain'){try{await navigator.clipboard.writeText(g.domain);toast('已复制域名：'+g.domain)}catch{prompt('复制域名',g.domain)}}else if(a==='failed'){const key='failed:'+g.id;if(expandedPools.has(key))expandedPools.delete(key);else expandedPools.add(key);const open=expandedPools.has(key);b.setAttribute('aria-expanded',String(open));b.innerHTML=`${open?'▾ 收起':'▸ 展开'} 失效池 <span class="badge">${Object.keys(g.failed_ips||{}).length}</span>`;document.getElementById('failed-'+g.id).hidden=!open}else if(a==='pool'){if(expandedPools.has(g.id))expandedPools.delete(g.id);else expandedPools.add(g.id);b.setAttribute('aria-expanded',String(expandedPools.has(g.id)));b.innerHTML=`${expandedPools.has(g.id)?'▾ 收起':'▸ 展开'} 正常 IP 池 <span class="badge">${activeIps(g).length}</span>`;document.getElementById('pool-'+g.id).hidden=!expandedPools.has(g.id)}else if(a==='switch')openSwitch(g);else if(a==='edit')edit(g);else if(a==='copy'){try{await navigator.clipboard.writeText(g.link);toast('已复制动态域名节点')}catch{prompt('复制动态域名节点',g.link)}}else if(a==='delete'){if(confirm('删除 '+g.domain+'？将同时删除该域名的 Cloudflare A / AAAA 记录及本地 IP 池。'))try{b.disabled=true;await api('delete',{id:g.id});toast('域名及对应 Cloudflare 地址记录已删除');refresh()}catch(e){toast(e.message)}finally{b.disabled=false}}else if(a==='rotate'){if(confirm('选择延迟最低的可用 IP 并更新 '+g.domain+' 的 DNS？'))action(a,[g.id])}else action(a,[g.id])};
if(password)refresh(true);setInterval(()=>{if(password)refresh()},3000);

function openSwitch(g){
 const f=$('#switch-form');f.elements.id.value=g.id;$('#switch-domain').textContent=g.domain;
 const available=activeIps(g);f.elements.ip.innerHTML=available.map(ip=>{const r=g.results?.find(r=>r.ip===ip);return `<option value="${esc(ip)}">${esc(ip)}${ip===g.current?'（当前 IP）':r?(r.ok?'（最近测活可用）':'（最近测活失败）'):''}</option>`}).join('');
 f.elements.ip.value=available.find(ip=>ip!==g.current)||available[0]||'';$('#switch-submit').disabled=!available.length;if(!available.length)toast('正常池暂无 IP，失效 IP 等待分级复活检测');$('#switcher').showModal();
}
$('#switch-close').onclick=()=>$('#switcher').close();
$('#switch-form').onsubmit=async e=>{
 e.preventDefault();const b=$('#switch-submit');b.disabled=true;
 try{await api('switch',Object.fromEntries(new FormData(e.target)));$('#switcher').close();toast('已开始检测所选 IP，切换结果将在域名卡片显示');refresh()}
 catch(e){toast(e.message)}finally{b.disabled=false}
};

function selectedPort(){return Number($('#extract-port').value)}
function renderExtractTargets(){
 if(!state)return;const target=$('#extract-target'),selected=target.value;
 target.innerHTML='<option value="">请选择同端口子域名</option>'+state.groups.filter(g=>(g.port||443)===selectedPort()).map(g=>`<option value="${esc(g.id)}">${esc(g.domain)} · ${g.port||443}</option>`).join('');
 if(state.groups.some(g=>g.id===selected&&(g.port||443)===selectedPort()))target.value=selected;
}
function renderExtractPool(){
 const bucket=extractedData?.port_groups[String(selectedPort())];extractedIps=bucket?.ips||[];
 $('#extracted-ips').value=extractedIps.join('\n');
 for(const id of ['#extract-copy','#extract-new','#extract-append'])$(id).disabled=!extractedIps.length;
 renderExtractTargets();
}
$('#extract-port').onchange=renderExtractPool;
$('#extract-input').oninput=()=>{extractedData=null;extractedIps=[];$('#extract-result').hidden=true};
$('#extract-form').onsubmit=async e=>{
 e.preventDefault();const b=$('#extract-submit');b.disabled=true;
 try{const text=$('#extract-input').value,d=await api('extract',{text});
 if(text!==$('#extract-input').value)return;
 extractedData=d;extractedText=text;$('#extract-result').hidden=false;
 const a=d.port_groups['443'],c=d.port_groups['8443'];
 $('#extract-port').value=a.ips.length?'443':'8443';
 $('#extract-summary').textContent=`共 ${d.total} 条：443 池 ${a.ips.length} 个 IP（去重 ${a.duplicates} 条），8443 池 ${c.ips.length} 个 IP（去重 ${c.duplicates} 条）；跳过 ${d.domain_count} 条域名节点、${d.other_port_count} 条其他端口、${d.invalid} 条无效输入。`;
 $('#port-import-submit').disabled=!d.ips.length;renderExtractPool();
 }catch(e){toast(e.message)}finally{b.disabled=false}
};
$('#extract-copy').onclick=async()=>{try{await navigator.clipboard.writeText(extractedIps.join('\n'));toast('已复制该端口 IP 池')}catch{$('#extracted-ips').focus();$('#extracted-ips').select();toast('请复制已选中的 IP')}};
function templateForPool(){const f=$('#port-import-form'),tid=f.elements['template_'+selectedPort()].value;return state?.templates?.find(t=>t.id===tid)?.node||f.elements.node.value.trim()||extractedData?.port_groups[String(selectedPort())]?.node||''}
function setNodePort(uri,port){try{const u=new URL(uri);u.port=String(port);return u.toString()}catch{return uri}}
$('#extract-new').onclick=()=>{edit();const f=$('#group-form');f.elements.ips.value=extractedIps.join('\n');f.elements.node.value=setNodePort(templateForPool(),selectedPort());updateDomainPreview()};
$('#extract-append').onclick=()=>{const g=state.groups.find(g=>g.id===$('#extract-target').value);if(!g){toast('请选择同端口子域名');return}if((g.port||443)!==selectedPort()){toast('端口不匹配');return}edit(g);$('#group-form').elements.ips.value=[...new Set([...g.ips,...extractedIps])].join('\n')};
$('#port-import-form').onsubmit=async e=>{
 e.preventDefault();if(!extractedData){toast('请先识别输入内容');return}
 const b=$('#port-import-submit');b.disabled=true;
 try{const d=Object.fromEntries(new FormData(e.target));d.enabled=e.target.elements.enabled.checked;d.text=extractedText;
 const result=await api('import-ports',d);toast('已保存：'+result.groups.map(g=>`${g.domain}（${g.port} / ${g.count} IP）`).join('、'));refresh();
 }catch(e){toast(e.message)}finally{b.disabled=false}
};
function updateDomainPreview(){
 const f=$('#group-form');let domain=completeDomain(f.elements.domain.value);
 try{const u=new URL(f.elements.node.value.trim()),port=Number(u.port||443);if(domain.includes('.')&&[443,8443].includes(port)){const i=domain.indexOf('.');domain=domain.slice(0,i).replace(/-(1|2)$/,'')+(port===443?'-1':'-2')+domain.slice(i);$('#domain-preview').textContent=`保存后的域名：${domain} · ${port} 端口`;return}}catch{}
 $('#domain-preview').textContent='默认 example.com，按端口自动添加 -1（443）或 -2（8443）；也支持完整域名。';
}
$('#group-form').elements.domain.addEventListener('input',updateDomainPreview);
$('#group-form').elements.node.addEventListener('input',updateDomainPreview);

function completeDomain(value){const domain=value.trim().toLowerCase().replace(/\.$/,'');return domain&&!domain.includes('.')?domain+'.example.com':domain}
$('#port-import-form').elements.domain.addEventListener('input',e=>{
 const domain=completeDomain(e.target.value),i=domain.indexOf('.');
 if(i<1){$('#import-domain-preview').textContent='默认 example.com；按端口自动生成 -1 和 -2 子域名，也支持完整域名。';return}
 const prefix=domain.slice(0,i).replace(/-(1|2)$/,''),rest=domain.slice(i);
 $('#import-domain-preview').textContent=`将生成 ${prefix}-1${rest}（443）和 ${prefix}-2${rest}（8443）。`;
});

function renderTemplates(){
 const ts=state?.templates||[];
 for(const select of document.querySelectorAll('[data-template-select]')){
  const value=select.value,html='<option value="">'+(select.name==='template_id'?'手动填写节点':'使用临时模板或输入节点')+'</option>'+ts.map(t=>`<option value="${esc(t.id)}">${esc(t.name)} · ${t.port} 端口</option>`).join('');
  if(select._options!==html){select.innerHTML=html;select._options=html;if(ts.some(t=>t.id===value))select.value=value}
 }
 const list=$('#template-list'),html=ts.length?ts.map(t=>`<div class="template-row"><span><b>${esc(t.name)}</b><small>${t.port} 端口</small></span><div class="actions"><button type="button" data-template-action="edit" data-id="${esc(t.id)}">编辑</button><button type="button" data-template-action="delete" data-id="${esc(t.id)}">删除</button></div></div>`).join(''):'<p>暂无模板，先保存一条完整 VLESS 链接，之后导入可直接选择。</p>';
 if(list._markup!==html){list.innerHTML=html;list._markup=html}
}
$('#template-form').onsubmit=async e=>{
 e.preventDefault();const button=$('#template-submit');button.disabled=true;
 try{await api('template',Object.fromEntries(new FormData(e.target)));e.target.reset();toast('模板已保存，可在导入时选择');await refresh()}
 catch(e){toast(e.message)}finally{button.disabled=false}
};
$('#template-reset').onclick=()=>$('#template-form').reset();
$('#template-list').onclick=async e=>{
 const b=e.target.closest('button[data-template-action]');if(!b)return;
 const t=state?.templates?.find(t=>t.id===b.dataset.id);if(!t)return;
 if(b.dataset.templateAction==='edit'){const f=$('#template-form');for(const k of ['id','name','node'])f.elements[k].value=t[k];f.elements.name.focus()}
 else if(confirm('删除模板“'+t.name+'”？已创建的节点组会保留原参数。')){
  try{await api('template-delete',{id:t.id});if($('#template-form').elements.id.value===t.id)$('#template-form').reset();toast('模板已删除');refresh()}catch(e){toast(e.message)}
 }
};
$('#group-form').elements.template_id.onchange=e=>{
 const t=state?.templates?.find(t=>t.id===e.target.value);if(t){$('#group-form').elements.node.value=t.node;updateDomainPreview()}
};
