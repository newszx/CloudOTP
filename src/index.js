import {
  constantTimeEqual,
  createSession,
  decryptText,
  encryptText,
  normalizeSecret,
  sha256,
  totp,
  verifySession,
} from "./crypto.js";

const COOKIE = "cloudotp_admin";
const COLORS = new Set(["green", "blue", "orange", "purple", "gray"]);

function esc(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function cookieValue(request, name) {
  const match = request.headers.get("Cookie")?.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : "";
}

function randomToken(bytes = 18) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  let binary = "";
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function createLoginToken(env) {
  return encryptText(`${Date.now()}:${randomToken()}`, env.SESSION_SECRET);
}

async function verifyLoginToken(token, env, now = Date.now()) {
  try {
    const value = await decryptText(String(token || ""), env.SESSION_SECRET);
    const separator = value.indexOf(":");
    const issuedAt = Number(value.slice(0, separator));
    const nonce = value.slice(separator + 1);
    return separator > 0 && Number.isFinite(issuedAt) && nonce.length >= 16 && issuedAt <= now + 60_000 && now - issuedAt <= 600_000;
  } catch {
    return false;
  }
}

function response(body, status = 200, headers = {}) {
  const result = new Response(body, { status, headers });
  result.headers.set("Content-Type", "text/html; charset=utf-8");
  result.headers.set("Cache-Control", "no-store, private");
  result.headers.set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'self'");
  result.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  result.headers.set("Referrer-Policy", "same-origin");
  result.headers.set("X-Content-Type-Options", "nosniff");
  result.headers.set("X-Frame-Options", "DENY");
  return result;
}

function redirect(location, headers = {}) {
  return response("", 303, { Location: location, ...headers });
}

function json(value, status = 200) {
  const result = response(JSON.stringify(value), status);
  result.headers.set("Content-Type", "application/json; charset=utf-8");
  return result;
}

function flashRedirect(location, message, kind = "success") {
  return redirect(`${location}${location.includes("?") ? "&" : "?"}${new URLSearchParams({ message, kind })}`);
}

function validateEnv(env) {
  for (const name of ["ADMIN_PASSWORD", "SESSION_SECRET", "APP_ENCRYPTION_KEY"]) {
    if (!env[name] || String(env[name]).startsWith("replace-with-")) throw new Error(`请先配置 ${name}`);
  }
  if (env.ADMIN_PASSWORD.length < 12) throw new Error("ADMIN_PASSWORD 至少需要 12 个字符");
}

async function sessionFor(request, env) {
  return verifySession(cookieValue(request, COOKIE), env.SESSION_SECRET);
}

async function requireAdmin(request, env) {
  const session = await sessionFor(request, env);
  return session || null;
}

async function formData(request, session) {
  const form = await request.formData();
  if (!session || !form.get("csrf") || form.get("csrf") !== session.csrf) throw new Error("页面已过期，请刷新后重试");
  return form;
}

function statusFor(row) {
  if (!row.enabled) return ["已停用", "off"];
  if (!row.expires_at) return ["长期", "neutral"];
  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);
  const days = Math.floor((new Date(`${row.expires_at}T00:00:00Z`) - today) / 86_400_000);
  if (days < 0) return ["已过期", "expired"];
  if (days <= 7) return [`${days}天到期`, "warning"];
  return ["正常", "on"];
}

const CSS = `
:root{color-scheme:light;--background:#f8fafc;--foreground:#0f172a;--card:#fff;--card-foreground:#0f172a;--muted:#f1f5f9;--muted-foreground:#64748b;--border:#e2e8f0;--input:#cbd5e1;--primary:#0f172a;--primary-foreground:#fff;--secondary:#f8fafc;--secondary-foreground:#0f172a;--accent:#f1f5f9;--accent-foreground:#0f172a;--destructive:#dc2626;--destructive-foreground:#fff;--ring:#94a3b8;--success:#16a34a;--success-bg:#dcfce7;--warning:#d97706;--warning-bg:#fef3c7;--radius:12px;--shadow:0 1px 2px rgba(15,23,42,.05)}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--background);color:var(--foreground);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",sans-serif;letter-spacing:0}a{color:inherit;text-decoration:none}.top{border-bottom:1px solid var(--border);background:rgba(255,255,255,.85);backdrop-filter:blur(12px);padding:14px 0}.shell{width:min(1180px,calc(100% - 32px));margin:auto}.top .shell,.row,.topbar,.actions,.member-title,.inline{display:flex;align-items:center}.top .shell,.topbar{justify-content:space-between;gap:16px}.brand{font-size:18px;font-weight:800}.nav{display:flex;gap:8px}.app-shell{display:grid;grid-template-columns:240px minmax(0,1fr);min-height:100vh}.sidebar{position:sticky;top:0;height:100vh;border-right:1px solid var(--border);background:#fff;padding:18px 14px;display:flex;flex-direction:column;gap:18px}.sidebar-brand{display:flex;align-items:center;gap:10px;padding:6px 8px}.mark{width:36px;height:36px;border-radius:10px;background:var(--primary);color:#fff;display:grid;place-items:center;font-weight:900}.sidebar-brand strong{display:block}.sidebar-brand span,.sub,.muted{color:var(--muted-foreground)}.sidebar-brand span{font-size:12px}.side-nav{display:grid;gap:5px}.side-nav a,.side-nav button{justify-content:flex-start;width:100%;border:0;box-shadow:none;background:transparent;color:var(--muted-foreground);font-weight:700}.side-nav .active{background:var(--accent);color:var(--accent-foreground)}.side-footer{margin-top:auto;border:1px solid var(--border);border-radius:var(--radius);background:var(--secondary);padding:12px;color:var(--muted-foreground);font-size:12px}.main{min-width:0;padding:24px}.topbar{margin-bottom:18px}.title h1{margin:0;font-size:28px;line-height:1.2}.title p{margin:5px 0 0;color:var(--muted-foreground)}.layout-grid{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:16px;align-items:start}.kpi-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:12px}.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)}.card-pad{padding:16px}.kpi{padding:16px}.kpi span{color:var(--muted-foreground);font-size:13px}.kpi b{display:block;margin-top:8px;font-size:28px;line-height:1}.toolbar{display:grid;grid-template-columns:minmax(260px,1fr) 170px 96px;gap:10px;padding:12px;margin-bottom:12px}.table-card{overflow:hidden}.table-head{padding:15px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:12px}.table-head h2{margin:0;font-size:16px}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:880px}th,td{padding:12px 14px;border-bottom:1px solid var(--border);text-align:left;vertical-align:middle}th{height:40px;background:#fbfdff;color:var(--muted-foreground);font-size:12px;font-weight:800}tr:hover{background:#fafafa}.member-title{gap:10px}.avatar{width:34px;height:34px;border-radius:10px;background:var(--muted);display:grid;place-items:center;font-weight:900;color:#334155}.code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.totp{font:800 20px/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:1.5px;white-space:nowrap}.badge{display:inline-flex;align-items:center;gap:5px;height:24px;padding:0 8px;border-radius:999px;font-size:12px;font-weight:800;background:var(--secondary);color:var(--secondary-foreground)}.badge.neutral,.badge.on{background:var(--success-bg);color:#166534}.badge.warning{background:var(--warning-bg);color:#92400e}.badge.off,.badge.expired,.badge.destructive{background:#fee2e2;color:#991b1b}.btn,button,input,select,textarea{font:inherit}.btn,button{appearance:none;border:1px solid var(--border);border-radius:10px;background:#fff;color:var(--foreground);min-height:36px;padding:8px 12px;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:7px;font-weight:750;box-shadow:var(--shadow);transition:background .12s,border-color .12s,transform .12s}.btn:hover,button:hover{background:var(--accent);border-color:var(--input)}.btn:active,button:active{transform:translateY(1px)}.primary{background:var(--primary);border-color:var(--primary);color:var(--primary-foreground)}.primary:hover{background:#1e293b}.danger{color:var(--destructive);border-color:#fecaca}.copy-code{background:var(--primary);border-color:var(--primary);color:#fff}.copy-code:hover{background:#1e293b}.copy-link{color:#166534;border-color:#bbf7d0;background:#f0fdf4}.copy-link:hover{background:#dcfce7}.ghost{background:#fff}.icon-btn{width:36px;padding:0}.pill-action{border-radius:999px}.action-form{display:inline-flex;margin:0}.row-actions{display:flex;gap:6px;flex-wrap:wrap}.icon{font-size:15px;line-height:1}.form-card{padding:16px}.form-card h2,.form-card h3{margin:0 0 10px;font-size:16px}label{display:block;margin:11px 0 5px;font-weight:750}input,select,textarea{width:100%;border:1px solid var(--input);border-radius:10px;background:#fff;color:var(--foreground);padding:10px 11px;outline:none}input:focus,select:focus,textarea:focus{border-color:var(--ring);box-shadow:0 0 0 3px rgba(148,163,184,.22)}textarea{min-height:74px;resize:vertical}.flash{padding:12px 14px;border-radius:var(--radius);background:var(--success-bg);color:#166534;margin-bottom:12px;font-weight:700}.flash.error{background:#fee2e2;color:#991b1b}.empty{text-align:center;padding:42px 16px;color:var(--muted-foreground)}.login{width:min(430px,calc(100% - 32px));margin:10vh auto;padding:24px}.login h1{margin:0 0 6px}.share-shell{min-height:calc(100vh - 65px);display:grid;place-items:center;padding:32px 16px;background:radial-gradient(circle at top,#dcfce7 0,transparent 36%),var(--background)}.share{width:min(500px,100%);text-align:center;padding:28px}.share h1{font-size:34px;margin:20px 0 6px}.share .totp{font-size:56px;letter-spacing:7px;margin:22px 0 8px}.bar{height:9px;background:var(--border);border-radius:999px;overflow:hidden;margin:18px 0}.bar i{display:block;height:100%;background:var(--success);transition:width .4s}.share-copy{width:100%;height:48px;background:var(--primary);border-color:var(--primary);color:#fff;border-radius:12px;font-size:16px}.note{font-size:13px;background:var(--secondary);border-radius:var(--radius);padding:11px;margin-top:12px;color:var(--muted-foreground)}.logs-table td{font-size:13px}.toast{position:fixed;left:50%;bottom:28px;z-index:20;transform:translate(-50%,14px);opacity:0;background:var(--primary);color:#fff;border-radius:999px;padding:10px 14px;font-size:13px;font-weight:800;box-shadow:0 18px 45px rgba(15,23,42,.28);pointer-events:none;transition:.18s}.toast.show{opacity:1;transform:translate(-50%,0)}[hidden]{display:none!important}@media(prefers-color-scheme:dark){:root{color-scheme:dark;--background:#020617;--foreground:#e2e8f0;--card:#0f172a;--card-foreground:#e2e8f0;--muted:#1e293b;--muted-foreground:#94a3b8;--border:#1e293b;--input:#334155;--primary:#e2e8f0;--primary-foreground:#020617;--secondary:#111827;--secondary-foreground:#e2e8f0;--accent:#1e293b;--accent-foreground:#f8fafc;--ring:#475569;--shadow:none}.top,.sidebar,.card,input,select,textarea,.btn,button{background:var(--card)}th{background:#111827}tr:hover{background:#111827}.copy-code,.share-copy,.primary,.toast{background:var(--primary);color:var(--primary-foreground);border-color:var(--primary)}.copy-code:hover,.share-copy:hover,.primary:hover{background:#cbd5e1}.copy-link{background:#052e16}.danger{background:#2a1214}.mark{background:var(--primary);color:var(--primary-foreground)}}@media(max-width:1050px){.app-shell{grid-template-columns:1fr}.sidebar{position:static;height:auto}.side-nav{grid-template-columns:repeat(4,1fr)}.side-footer{display:none}.layout-grid{grid-template-columns:1fr}.kpi-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:640px){.main{padding:16px}.topbar{align-items:flex-start;flex-direction:column}.toolbar{grid-template-columns:1fr}.kpi-grid{grid-template-columns:1fr 1fr}.side-nav{grid-template-columns:1fr 1fr}.share .totp{font-size:42px;letter-spacing:4px}table{min-width:760px}}
`;

function layout(title, content, session = null) {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · TOTP 看板</title><style>${CSS}</style></head><body>
  ${session ? "" : `<header class="top"><div class="shell"><a class="brand" href="/">CloudOTP</a></div></header>`}
  ${content}</body></html>`;
}

function messageBlock(url) {
  const message = url.searchParams.get("message");
  return message ? `<div class="flash ${url.searchParams.get("kind") === "error" ? "error" : ""}">${esc(message)}</div>` : "";
}

function adminShell(active, title, subtitle, body, session) {
  const nav = [
    ["看板", "/admin", "⌘"],
    ["访问记录", "/admin/logs", "↗"],
  ];
  return `<div class="app-shell"><aside class="sidebar"><a class="sidebar-brand" href="/admin"><span class="mark">✓</span><span><strong>CloudOTP</strong><span>2FA 分享控制台</span></span></a><nav class="side-nav">${nav.map(([name, href, icon]) => `<a class="btn ${active === href ? "active" : ""}" href="${href}"><span class="icon">${icon}</span>${name}</a>`).join("")}<form method="post" action="/logout"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><button><span class="icon">⏻</span>退出登录</button></form></nav><div class="side-footer"><strong>D1 已连接</strong><br>密钥加密保存，分享链接可随时重置。</div></aside><main class="main"><section class="topbar"><div class="title"><h1>${esc(title)}</h1><p>${esc(subtitle)}</p></div><div class="actions"><a class="btn" href="/admin/logs"><span class="icon">↗</span>访问记录</a><a class="btn primary" href="#add-member"><span class="icon">+</span>添加会员</a></div></section>${body}</main></div>`;
}

async function loginPage(url, csrf, error = "") {
  return layout("登录", `<main class="login card"><h1>管理员登录</h1><p class="muted">登录后管理会员、分享链接和实时验证码。</p>${error ? `<div class="flash error">${esc(error)}</div>` : messageBlock(url)}<form method="post"><input type="hidden" name="csrf" value="${esc(csrf)}"><label for="username">账号</label><input id="username" name="username" autocomplete="username" value="admin" required><label for="password">密码</label><input id="password" name="password" type="password" autocomplete="current-password" required><button class="primary" style="width:100%;margin-top:18px">登录</button></form></main>`);
}

async function dashboard(request, env, session, url) {
  const [{ results: vehicles }, { results: categories }, active, views] = await Promise.all([
    env.DB.prepare("SELECT * FROM vehicles ORDER BY code ASC").all(),
    env.DB.prepare("SELECT * FROM categories ORDER BY name ASC").all(),
    env.DB.prepare("SELECT COUNT(*) AS count FROM vehicles WHERE enabled = 1").first(),
    env.DB.prepare("SELECT COUNT(*) AS count FROM access_logs WHERE date(created_at) = date('now')").first(),
  ]);
  let expiring = 0;
  const rows = [];
  for (const vehicle of vehicles) {
    const [label, kind] = statusFor(vehicle);
    if (kind === "warning") expiring += 1;
    let token = "";
    try { token = await decryptText(vehicle.share_token_cipher, env.APP_ENCRYPTION_KEY); } catch { token = "无法解密"; }
    const shareUrl = `${url.origin}/s/${token}`;
    rows.push(`<tr class="member" data-member data-name="${esc(`${vehicle.name} ${vehicle.code} ${vehicle.account}`.toLowerCase())}" data-category="${esc(vehicle.category)}"><td><div class="member-title"><span class="avatar">${esc(vehicle.name.slice(0, 1).toUpperCase() || "?")}</span><span><strong>${esc(vehicle.name)}</strong><span class="sub">${vehicle.account ? esc(vehicle.account) : "未填写账号"}</span></span></div></td><td><span class="badge">${esc(vehicle.code)}</span></td><td><span class="badge">${esc(vehicle.category)}</span></td><td><span class="totp" data-code-id="${vehicle.id}" data-plain-code="">••• •••</span><div class="sub" data-remaining-id="${vehicle.id}">正在获取</div></td><td><span class="badge ${kind}">${label}</span>${vehicle.expires_at ? `<div class="sub">${esc(vehicle.expires_at)}</div>` : ""}</td><td><span class="badge ${vehicle.enabled ? "on" : "off"}">${vehicle.enabled ? "有效" : "停用"}</span><input type="hidden" value="${esc(shareUrl)}" data-copy></td><td><div class="row-actions"><button type="button" class="copy-code icon-btn" title="复制验证码" data-copy-code-button><span class="icon">⧉</span></button><button type="button" class="copy-link icon-btn" title="复制分享链接" data-copy-button><span class="icon">↗</span></button><form class="action-form" method="post" action="/admin/vehicles/${vehicle.id}/toggle"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><button class="ghost icon-btn" title="${vehicle.enabled ? "停用分享" : "启用分享"}"><span class="icon">${vehicle.enabled ? "⏸" : "▶"}</span></button></form><form class="action-form" method="post" action="/admin/vehicles/${vehicle.id}/rotate" onsubmit="return confirm('旧链接将立即失效，确定重置？')"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><button class="ghost icon-btn" title="重置链接"><span class="icon">↻</span></button></form><form class="action-form" method="post" action="/admin/vehicles/${vehicle.id}/delete" onsubmit="return confirm('确定删除此会员及访问记录？')"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><button class="danger icon-btn" title="删除"><span class="icon">×</span></button></form></div></td></tr>`);
  }
  const options = categories.map((category) => `<option value="${esc(category.name)}">${esc(category.name)}</option>`).join("");
  const body = `${messageBlock(url)}<section class="kpi-grid"><div class="card kpi"><span>会员总数</span><b>${vehicles.length}</b></div><div class="card kpi"><span>已启用</span><b>${active?.count || 0}</b></div><div class="card kpi"><span>7 天内到期</span><b>${expiring}</b></div><div class="card kpi"><span>今日访问</span><b>${views?.count || 0}</b></div></section><div class="layout-grid"><section><div class="card toolbar"><input id="search" placeholder="搜索名称、编号或账号"><select id="category-filter"><option value="">全部分类</option>${options}</select><span class="badge"><span id="visible-count">${vehicles.length}</span> 项</span></div><div class="card table-card"><div class="table-head"><h2>成员列表</h2><span class="sub">验证码每 30 秒自动更新</span></div><div class="table-wrap">${rows.length ? `<table><thead><tr><th>成员</th><th>编号</th><th>分类</th><th>验证码</th><th>状态</th><th>分享</th><th>操作</th></tr></thead><tbody id="members">${rows.join("")}</tbody></table>` : `<div class="empty"><strong>还没有会员</strong><br>用右侧表单添加第一个 TOTP 账号。</div>`}</div></div></section><aside class="card form-card" id="add-member"><h2>添加会员</h2><form method="post" action="/admin/vehicles"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><label>名称</label><input name="name" required maxlength="80" placeholder="OpenAI Team"><label>编号</label><input name="code" required maxlength="20" placeholder="001"><label>账号</label><input name="account" maxlength="160" placeholder="member@example.com"><label>分类</label><select name="category">${options}</select><label>到期日期</label><input name="expires_at" type="date"><label>Base32 密钥</label><input name="secret" required autocomplete="off" placeholder="JBSWY3DPEHPK3PXP"><label>备注</label><textarea name="notes" maxlength="2000" placeholder="内部备注，不会显示在分享页"></textarea><button class="primary" style="width:100%;margin-top:14px"><span class="icon">+</span>保存并生成链接</button></form><hr style="border:0;border-top:1px solid var(--border);margin:20px 0"><h3>添加分类</h3><form method="post" action="/admin/categories"><input type="hidden" name="csrf" value="${esc(session.csrf)}"><label>分类名称</label><input name="name" required maxlength="80"><label>颜色</label><select name="color"><option value="green">绿色</option><option value="blue">蓝色</option><option value="orange">橙色</option><option value="purple">紫色</option><option value="gray">灰色</option></select><button style="width:100%;margin-top:12px">添加分类</button></form></aside></div>`;
  const content = adminShell("/admin", "会员与验证码", "shadcn 风格后台 · 管理 TOTP、分享链接、到期状态和访问风险", body, session);
  return layout("管理看板", content, session).replace("</body>", `<script>
const search=document.querySelector('#search'),filter=document.querySelector('#category-filter'),members=[...document.querySelectorAll('[data-member]')],count=document.querySelector('#visible-count');function apply(){const q=search.value.trim().toLowerCase(),c=filter.value;let n=0;for(const el of members){const show=(!q||el.dataset.name.includes(q))&&(!c||el.dataset.category===c);el.hidden=!show;if(show)n++}count.textContent=n}search.addEventListener('input',apply);filter.addEventListener('change',apply);
function toast(text){let el=document.querySelector('.toast');if(!el){el=document.createElement('div');el.className='toast';document.body.appendChild(el)}el.textContent=text;el.classList.add('show');clearTimeout(window.__toastTimer);window.__toastTimer=setTimeout(()=>el.classList.remove('show'),1400)}
async function copyText(text){try{await navigator.clipboard.writeText(text)}catch{const area=document.createElement('textarea');area.value=text;area.style.position='fixed';area.style.opacity='0';document.body.appendChild(area);area.select();document.execCommand('copy');area.remove()}}
document.addEventListener('click',async e=>{const linkBtn=e.target.closest('[data-copy-button]'),codeBtn=e.target.closest('[data-copy-code-button]');if(!linkBtn&&!codeBtn)return;const member=e.target.closest('.member');if(linkBtn){const input=member.querySelector('[data-copy]');await copyText(input.value);linkBtn.innerHTML='<span class="icon">✓</span>';toast('分享链接已复制');setTimeout(()=>linkBtn.innerHTML='<span class="icon">↗</span>',1200)}if(codeBtn){const code=member.querySelector('[data-code-id]').dataset.plainCode;if(!code)return toast('验证码还在加载');await copyText(code);codeBtn.innerHTML='<span class="icon">✓</span>';toast('验证码已复制');setTimeout(()=>codeBtn.innerHTML='<span class="icon">⧉</span>',1200)}});
async function codes(){try{const r=await fetch('/api/admin/codes',{cache:'no-store'});if(!r.ok)return;for(const item of await r.json()){const code=document.querySelector('[data-code-id="'+item.id+'"]'),left=document.querySelector('[data-remaining-id="'+item.id+'"]');if(code){code.textContent=item.code.slice(0,3)+' '+item.code.slice(3);code.dataset.plainCode=item.code}if(left)left.textContent=item.remaining+' 秒后更新'}}catch{}}codes();setInterval(codes,1000);
</script></body>`);
}

async function sharePage(env, vehicle, token) {
  return layout("查看验证码", `<main class="share-shell"><section class="share card"><span class="badge neutral">${esc(vehicle.category)}</span><h1>${esc(vehicle.name)}</h1><p class="muted">编号 ${esc(vehicle.code)}${vehicle.account ? ` · ${esc(vehicle.account)}` : ""}</p><div class="totp" id="code" data-plain-code="">••• •••</div><p class="muted"><span id="remaining">--</span> 秒后更新</p><div class="bar"><i id="bar" style="width:100%"></i></div><button type="button" class="share-copy" id="copy-code"><span class="icon">⧉</span>复制验证码</button><p class="note">验证码属于敏感凭据，请勿截图或转发本页面。</p></section></main><script>function toast(text){let el=document.querySelector('.toast');if(!el){el=document.createElement('div');el.className='toast';document.body.appendChild(el)}el.textContent=text;el.classList.add('show');clearTimeout(window.__toastTimer);window.__toastTimer=setTimeout(()=>el.classList.remove('show'),1400)}async function copyText(text){try{await navigator.clipboard.writeText(text)}catch{const area=document.createElement('textarea');area.value=text;area.style.position='fixed';area.style.opacity='0';document.body.appendChild(area);area.select();document.execCommand('copy');area.remove()}}document.querySelector('#copy-code').addEventListener('click',async()=>{const code=document.querySelector('#code').dataset.plainCode;if(!code)return toast('验证码还在加载');await copyText(code);document.querySelector('#copy-code').innerHTML='<span class="icon">✓</span>已复制';toast('验证码已复制');setTimeout(()=>document.querySelector('#copy-code').innerHTML='<span class="icon">⧉</span>复制验证码',1200)});async function update(){try{const r=await fetch('/api/s/${esc(token)}/code',{cache:'no-store'});if(!r.ok)throw 0;const d=await r.json();document.querySelector('#code').textContent=d.code.slice(0,3)+' '+d.code.slice(3);document.querySelector('#code').dataset.plainCode=d.code;document.querySelector('#remaining').textContent=d.remaining;document.querySelector('#bar').style.width=(d.remaining/30*100)+'%'}catch{document.querySelector('#code').textContent='链接已失效';document.querySelector('#copy-code').disabled=true}}update();setInterval(update,1000)</script>`);
}

async function findShared(env, token) {
  if (token.length < 12) return null;
  return env.DB.prepare("SELECT * FROM vehicles WHERE share_token_hash = ? AND enabled = 1").bind(await sha256(token)).first();
}

async function handle(request, env) {
  validateEnv(env);
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method.toUpperCase();
  const secureCookie = url.protocol === "https:" ? "; Secure" : "";
  if (path === "/health") return json({ status: "ok", runtime: "cloudflare-workers", database: "d1" });

  if (path === "/login") {
    if (method === "GET") {
      if (await sessionFor(request, env)) return redirect("/admin");
      return response(await loginPage(url, await createLoginToken(env)));
    }
    if (method === "POST") {
      const form = await request.formData();
      if (!await verifyLoginToken(form.get("csrf"), env)) return response(await loginPage(url, await createLoginToken(env), "页面已过期，请刷新后重试"), 403);
      if (!constantTimeEqual(form.get("username"), "admin") || !constantTimeEqual(form.get("password"), env.ADMIN_PASSWORD)) return response(await loginPage(url, await createLoginToken(env), "账号或密码不正确"), 401);
      const csrf = randomToken();
      const signed = await createSession(env.SESSION_SECRET, csrf);
      return redirect("/admin", { "Set-Cookie": `${COOKIE}=${encodeURIComponent(signed)}; Path=/; HttpOnly${secureCookie}; SameSite=Lax; Max-Age=43200` });
    }
  }

  if (path === "/") return redirect((await sessionFor(request, env)) ? "/admin" : "/login");

  const shareMatch = path.match(/^\/s\/([A-Za-z0-9_-]+)$/);
  if (shareMatch && method === "GET") {
    const vehicle = await findShared(env, shareMatch[1]);
    if (!vehicle) return response(layout("链接无效", `<main class="share card"><h1>分享链接无效</h1><p class="muted">链接可能已被停用或重置。</p></main>`), 404);
    await env.DB.prepare("INSERT INTO access_logs(vehicle_id, ip_address, user_agent) VALUES (?, ?, ?)").bind(vehicle.id, (request.headers.get("CF-Connecting-IP") || "unknown").slice(0, 64), (request.headers.get("User-Agent") || "unknown").slice(0, 255)).run();
    return response(await sharePage(env, vehicle, shareMatch[1]));
  }

  const shareApi = path.match(/^\/api\/s\/([A-Za-z0-9_-]+)\/code$/);
  if (shareApi && method === "GET") {
    const vehicle = await findShared(env, shareApi[1]);
    if (!vehicle) return json({ error: "not_found" }, 404);
    const secret = await decryptText(vehicle.secret_cipher, env.APP_ENCRYPTION_KEY);
    return json({ code: await totp(secret), remaining: 30 - (Math.floor(Date.now() / 1000) % 30), name: vehicle.name, vehicle_code: vehicle.code });
  }

  const session = await requireAdmin(request, env);
  if (!session) return redirect("/login");

  if (path === "/admin" && method === "GET") return response(await dashboard(request, env, session, url));

  if (path === "/logout" && method === "POST") {
    await formData(request, session);
    return redirect("/login", { "Set-Cookie": `${COOKIE}=; Path=/; HttpOnly${secureCookie}; SameSite=Lax; Max-Age=0` });
  }

  if (path === "/admin/vehicles" && method === "POST") {
    try {
      const form = await formData(request, session);
      const name = String(form.get("name") || "").trim();
      const code = String(form.get("code") || "").trim();
      const category = String(form.get("category") || "未分类").trim() || "未分类";
      if (!name || !code) throw new Error("名称和编号不能为空");
      if (!await env.DB.prepare("SELECT id FROM categories WHERE name = ?").bind(category).first()) throw new Error("请选择有效分类");
      const secret = normalizeSecret(String(form.get("secret") || ""));
      const token = randomToken(9);
      await env.DB.prepare("INSERT INTO vehicles(name, code, category, account, expires_at, notes, secret_cipher, share_token_cipher, share_token_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(name, code, category, String(form.get("account") || "").trim(), form.get("expires_at") || null, String(form.get("notes") || "").trim(), await encryptText(secret, env.APP_ENCRYPTION_KEY), await encryptText(token, env.APP_ENCRYPTION_KEY), await sha256(token)).run();
      return flashRedirect("/admin", "会员已添加，专属链接已生成");
    } catch (error) {
      return flashRedirect("/admin", `保存失败：${error.message.includes("UNIQUE") ? "编号已经存在" : error.message}`, "error");
    }
  }

  if (path === "/admin/categories" && method === "POST") {
    try {
      const form = await formData(request, session);
      const name = String(form.get("name") || "").trim();
      const color = COLORS.has(form.get("color")) ? form.get("color") : "green";
      if (!name) throw new Error("分类名称不能为空");
      await env.DB.prepare("INSERT INTO categories(name, color) VALUES (?, ?)").bind(name, color).run();
      return flashRedirect("/admin", "分类已添加");
    } catch (error) {
      return flashRedirect("/admin", `保存失败：${error.message.includes("UNIQUE") ? "分类已经存在" : error.message}`, "error");
    }
  }

  const vehicleAction = path.match(/^\/admin\/vehicles\/(\d+)\/(toggle|rotate|delete)$/);
  if (vehicleAction && method === "POST") {
    await formData(request, session);
    const id = Number(vehicleAction[1]);
    const action = vehicleAction[2];
    if (action === "toggle") await env.DB.prepare("UPDATE vehicles SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id = ?").bind(id).run();
    if (action === "rotate") {
      const token = randomToken(9);
      await env.DB.prepare("UPDATE vehicles SET share_token_cipher = ?, share_token_hash = ?, enabled = 1 WHERE id = ?").bind(await encryptText(token, env.APP_ENCRYPTION_KEY), await sha256(token), id).run();
    }
    if (action === "delete") await env.DB.batch([env.DB.prepare("DELETE FROM access_logs WHERE vehicle_id = ?").bind(id), env.DB.prepare("DELETE FROM vehicles WHERE id = ?").bind(id)]);
    return flashRedirect("/admin", action === "rotate" ? "已生成新链接，旧链接立即失效" : action === "delete" ? "会员已删除" : "分享状态已更新");
  }

  if (path === "/api/admin/codes" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT id, secret_cipher, enabled FROM vehicles ORDER BY code ASC").all();
    const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
    return json(await Promise.all(results.map(async (row) => ({ id: row.id, enabled: Boolean(row.enabled), code: await totp(await decryptText(row.secret_cipher, env.APP_ENCRYPTION_KEY)), remaining }))));
  }

  if (path === "/admin/logs" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT access_logs.*, vehicles.name, vehicles.code FROM access_logs JOIN vehicles ON vehicles.id = access_logs.vehicle_id ORDER BY access_logs.created_at DESC LIMIT 300").all();
    const rows = results.map((row) => `<tr><td><strong>${esc(row.name)}</strong><div class="sub">${esc(row.code)}</div></td><td class="code">${esc(row.ip_address)}</td><td>${esc(row.user_agent)}</td><td>${esc(row.created_at)} UTC</td></tr>`).join("");
    const body = `<div class="card table-card"><div class="table-head"><h2>最近访问记录</h2><span class="sub">最多显示 300 条</span></div><div class="table-wrap">${rows ? `<table class="logs-table"><thead><tr><th>成员</th><th>IP</th><th>User-Agent</th><th>时间</th></tr></thead><tbody>${rows}</tbody></table>` : `<div class="empty">暂无访问记录</div>`}</div></div>`;
    return response(layout("访问记录", adminShell("/admin/logs", "访问记录", "查看分享页访问 IP、设备和时间，用来排查异常访问", body, session), session));
  }

  return response(layout("未找到", `<main class="share card"><h1>404</h1><p class="muted">页面不存在。</p></main>`, session), 404);
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (error) {
      console.error(error);
      return response(layout("配置错误", `<main class="share card"><h1>服务暂不可用</h1><p class="muted">${esc(error.message)}</p><p class="note">请在 Cloudflare Worker 设置中检查 D1 绑定和三个 Secret。</p></main>`), 500);
    }
  },
};
