const $ = id => document.getElementById(id);
let me, instances = [], selected, socket, target, poll;
let noticeTimer;
const controlKey = () => selected ? sessionStorage.getItem(`tom-control-${selected.id}`) : '';
function notice(text) { $('notice').textContent = text; $('notice').hidden = false; clearTimeout(noticeTimer); noticeTimer = setTimeout(() => $('notice').hidden = true, 9000); }
async function api(path, body, extra = {}) {
  const response = await fetch(path, {method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin',
    headers: {'Content-Type':'application/json', ...extra}, ...(body === undefined ? {} : {body:JSON.stringify(body)})});
  const data = await response.json();
  if (!response.ok) { if(response.status === 401) $('login-dialog').showModal(); throw new Error(data.error || 'Request failed'); }
  return data;
}
const base = () => `/api/instances/${selected.id}`;
function element(tag, text, cls) { const e = document.createElement(tag); if(text !== undefined) e.textContent = text; if(cls) e.className = cls; return e; }
function bind(id, fn) { $(id).addEventListener('click', async () => { const button = $(id); button.disabled = true; try {await fn();} catch(e) {notice(e.message);} finally {button.disabled = false;} }); }
function renderInstances() {
  $('instances').replaceChildren(...instances.map(i => {
    const b = element('button', undefined, 'instance' + (selected?.id === i.id ? ' selected' : ''));
    b.append(element('span', '✦', 'instance-icon')); const title = element('span', i.name);
    title.append(element('small', i.state === 'human' ? 'You have browser control' : i.state)); b.append(title);
    b.addEventListener('click', () => choose(i)); return b;
  }));
}
function renderSelected() {
  $('welcome').hidden = !!selected; $('workspace').hidden = !selected;
  if(!selected) return;
  $('title').textContent = selected.name; $('state').textContent = selected.state === 'human' ? 'Browser control paused the assistant' : selected.state;
  $('start').hidden = selected.state !== 'stopped'; $('stop').hidden = selected.state === 'stopped';
  $('take-control').hidden = selected.state !== 'running'; $('release-control').hidden = selected.state !== 'human' || !controlKey();
  $('browser-mode').textContent = selected.state === 'human' ? 'Human control' : 'View only';
  $('type-form').hidden = selected.state !== 'human' || !controlKey();
  $('url').disabled = selected.state !== 'human';
  $('navigate-form').querySelector('button').disabled = selected.state !== 'human' || !controlKey();
  $('console-button').disabled = selected.state !== 'running';
  $('saved-host').replaceChildren(...selected.credentials.map(host => {const o=element('option',host);o.value=host;return o;}));
}
async function refresh() {
  instances = await api('/api/instances');
  if(selected) selected = instances.find(i => i.id === selected.id);
  renderInstances(); renderSelected();
  if(!selected) return;
  const jobs = await api(base()+'/jobs');
  $('queue').replaceChildren(...jobs.slice(0,5).map(j => element('div',`${j.state} · ${j.message.slice(0,65)}`, 'job')));
  if(selected.state === 'running') {
    const data = await api(base()+'/history');
    const nodes = (data.messages || []).filter(m => ['user','assistant'].includes(m.role)).map(m => {
      const text = typeof m.content === 'string' ? m.content : (m.content || []).filter(c=>c.type==='text').map(c=>c.text).join('\n');
      const d = element('div', undefined, 'message ' + m.role); d.append(element('span',m.role==='user'?'You':selected.name,'message-label'),element('span',text));return d;
    });
    $('messages').replaceChildren(...nodes); $('messages').scrollTop = $('messages').scrollHeight;
  } else if(!jobs.length) $('messages').replaceChildren(element('div','Ask your assistant to research, plan, or get something done.','message'));
  if(['running','human'].includes(selected.state)) await refreshTabs();
  else disconnect();
}
async function choose(i) { disconnect(); selected=i;target=null;renderInstances();renderSelected();try{await refresh();}catch(e){notice(e.message);} }
function disconnect() { if(socket)socket.close();socket=null; $('browser-image').hidden=true;$('browser-empty').hidden=false; }
async function refreshTabs() {
  const tabs = await api(base()+'/tabs');
  if(!tabs.length)return;
  if(!tabs.some(t=>t.id===target))target=tabs[0].id;
  $('tabs').replaceChildren(...tabs.map(t=>{const o=element('option',t.title||t.url||'Tab');o.value=t.id;return o;}));$('tabs').value=target;
  if(document.activeElement!==$('url'))$('url').value=tabs.find(t=>t.id===target)?.url||'';
  if(!socket || socket.readyState > 1) connect();
}
function connect() {
  if(socket) socket.close();
  const iid=selected.id;
  socket=new WebSocket(`${location.protocol==='https:'?'wss':'ws'}://${location.host}/api/instances/${iid}/stream?target=${encodeURIComponent(target)}`);
  socket.onmessage=e=>{const msg=JSON.parse(e.data);if(msg.type==='frame' && selected?.id===iid){$('browser-image').src=`data:image/jpeg;base64,${msg.data}`;$('browser-image').hidden=false;$('browser-empty').hidden=true;}else if(msg.error)notice(msg.error);};
  socket.onerror=()=>notice('Browser connection interrupted. It will reconnect when available.');
}
function remote(action) { if(selected?.state!=='human'||!controlKey())return; if(socket?.readyState===1)socket.send(JSON.stringify({...action,token:controlKey()})); }
$('browser-image').addEventListener('click',e=>{const r=e.target.getBoundingClientRect();remote({type:'click',x:(e.clientX-r.left)*1280/r.width,y:(e.clientY-r.top)*800/r.height});});
$('browser-image').addEventListener('keydown',e=>{if(selected?.state!=='human')return;e.preventDefault();if(e.key.length===1)remote({type:'text',text:e.key});else remote({type:'key',key:e.key});});
$('browser-image').addEventListener('paste',e=>{e.preventDefault();remote({type:'text',text:e.clipboardData.getData('text')});});
$('browser-image').addEventListener('wheel',e=>{if(selected?.state!=='human')return;e.preventDefault();const r=e.target.getBoundingClientRect();remote({type:'scroll',x:(e.clientX-r.left)*1280/r.width,y:(e.clientY-r.top)*800/r.height,dx:e.deltaX,dy:e.deltaY});},{passive:false});
$('tabs').addEventListener('change',()=>{target=$('tabs').value;connect();});
bind('start',async()=>{notice('Starting your assistant and browser…');await api(base()+'/start',{});await refresh();});
bind('stop',async()=>{await api(base()+'/stop',{});disconnect();await refresh();});
bind('take-control',async()=>{const r=await api(base()+'/take-control',{});sessionStorage.setItem(`tom-control-${selected.id}`,r.token);await refresh();notice('Assistant paused. You can now use its browser.');});
bind('release-control',async()=>{await api(base()+'/release-control',{}, {'X-Tom-Control':controlKey()});sessionStorage.removeItem(`tom-control-${selected.id}`);await refresh();});
bind('memory-button',async()=>{$('memory-text').textContent=(await api(base()+'/memory')).text;$('memory-dialog').showModal();});
bind('credentials-button',async()=>{$('credentials-dialog').showModal();});
bind('console-button',async()=>{const popup=window.open('about:blank','_blank');try{const r=await api(base()+'/console-launch',{});if(popup)popup.location=r.url;else location.href=r.url;}catch(e){popup?.close();throw e;}});
bind('new-assistant',async()=>{$('assistant-owner').replaceChildren(...me.invited_users.map(u=>{const o=element('option',u);o.value=u;return o;}));$('create-dialog').showModal();});
document.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',()=>b.closest('dialog').close()));
function form(id,fn){$(id).addEventListener('submit',async e=>{e.preventDefault();const b=e.target.querySelector('button[type=submit]');if(b)b.disabled=true;try{await fn();}catch(error){notice(error.message);}finally{if(b)b.disabled=false;}});}
form('create-form',async()=>{const i=await api('/api/instances',{name:$('assistant-name').value,owner:$('assistant-owner').value});$('create-dialog').close();$('assistant-name').value='';await choose(i);});
form('chat-form',async()=>{await api(base()+'/jobs',{id:crypto.randomUUID(),message:$('message').value});$('message').value='';notice('Message saved. It will run when an active slot is available.');await refresh();});
form('navigate-form',async()=>{await api(base()+'/browser',{type:'navigate',target,url:$('url').value},{'X-Tom-Control':controlKey()});});
form('type-form',async()=>{remote({type:'text',text:$('browser-text').value});$('browser-text').value='';});
form('key-form',async()=>{await api(base()+'/credentials',{kind:'openai',value:$('api-key').value});$('api-key').value='';notice('API key encrypted and saved. Stop and start the assistant to refresh it.');await refresh();});
form('website-form',async()=>{await api(base()+'/credentials',{kind:'website',host:$('credential-host').value,username:$('credential-username').value,password:$('credential-password').value});$('credential-password').value='';$('credential-username').value='';notice('Login encrypted and saved.');await refresh();});
form('fill-form',async()=>{await api(base()+'/browser',{type:'fill-credential',target,host:$('saved-host').value,username_selector:$('username-selector').value,password_selector:$('password-selector').value},{'X-Tom-Control':controlKey()});$('credentials-dialog').close();notice('Login filled. Review the page before submitting.');});
form('login-form',async()=>{await api('/api/local-login',{token:$('local-token').value});$('local-token').value='';$('login-dialog').close();await init();});
async function init(){try{me=await api('/api/me');$('identity').textContent=me.email;$('new-assistant').hidden=!me.admin;$('capacity').textContent=`${me.max_active} active assistant${me.max_active===1?'':'s'} at a time`;$('model').textContent=`${me.model} · Guarded execution`;await refresh();clearInterval(poll);poll=setInterval(()=>refresh().catch(e=>notice(e.message)),5000);}catch(e){notice(e.message);}}
await init();
