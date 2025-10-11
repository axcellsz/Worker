// ---------- CONFIG ----------
const rootDomain = "";
const serviceName = "";
const APP_DOMAIN = `vip.myxl.me`;
const PROTOCOLS = ["vless", "trojan", "ss"];
const PROXY_PER_PAGE = 24;
// Konstanta yang tidak digunakan sebelumnya sudah dihapus

// ---------- HELPERS ----------
function tryUrlDecode(s = '') {
  try { return /%[0-9A-Fa-f]{2}/.test(s) ? decodeURIComponent(s) : s; }
  catch { return s; }
}

function esc(s = '') {
  return String(s)
    .replace(/&/g, '&').replace(/</g, '<').replace(/>/g, '>').replace(/"/g, '"');
}

// --- FUNGSI PARSE VLESS (Support gRPC) ---
function parseVlessUri(uri) {
  const u = new URL(uri);
  const network = u.searchParams.get('type') || 'tcp';
  
  const path = tryUrlDecode(u.searchParams.get('path') || '/'); 
  const serviceName = tryUrlDecode(u.searchParams.get('serviceName') || '');
  const host = u.searchParams.get('host') || u.searchParams.get('sni') || u.hostname;
  
  return {
    protocol: 'vless',
    remark: decodeURIComponent(u.hash.substring(1)) || 'VLESS',
    server: u.hostname,
    port: parseInt(u.port, 10),
    password: decodeURIComponent(u.username),
    network: network,
    security: u.searchParams.get('security') || 'none',
    sni: u.searchParams.get('sni') || u.searchParams.get('host') || u.hostname,
    host: host,
    path: path,
    serviceName: serviceName || (network === 'grpc' ? path : ''),
  };
}

// --- FUNGSI PARSE VMESS (Support gRPC) ---
function parseVmessUri(uri){
  const base64Part = uri.substring('vmess://'.length).trim();
  const decodedStr = atob(base64Part);
  const decoded = JSON.parse(decodedStr);
  
  const network = decoded.net || 'tcp';
  const path = decoded.path || '/';

  return {
      protocol: 'vmess',
      remark: decoded.ps || 'VMess',
      server: decoded.add,
      port: parseInt(decoded.port, 10),
      password: decoded.id,
      alterId: parseInt(decoded.aid, 10) || 0,
      network: network,
      security: decoded.tls === 'tls' ? 'tls' : 'none',
      sni: decoded.sni || decoded.host || decoded.add,
      host: decoded.host || decoded.sni || decoded.add,
      path: path,
      serviceName: decoded.serviceName || (network === 'grpc' ? path : ''),
  };
}

// --- FUNGSI PARSE TROJAN (Support gRPC) ---
function parseTrojanUri(uri) {
  const u = new URL(uri);
  const network = u.searchParams.get('type') || 'tcp';
  
  const path = tryUrlDecode(u.searchParams.get('path') || '/');
  const serviceName = tryUrlDecode(u.searchParams.get('serviceName') || '');
  const host = u.searchParams.get('host') || u.searchParams.get('sni') || u.hostname;
  
  return {
    protocol: 'trojan',
    remark: decodeURIComponent(u.hash.substring(1)) || 'Trojan',
    server: u.hostname,
    port: parseInt(u.port, 10),
    password: decodeURIComponent(u.username),
    network: network,
    security: u.searchParams.get('security') || 'tls',
    sni: u.searchParams.get('sni') || u.searchParams.get('host') || u.hostname,
    host: host,
    path: path,
    serviceName: serviceName || (network === 'grpc' ? path : ''),
  };
}

// --- FUNGSI PARSE SHADOWSOCKS ---
function parseShadowsocksUri(uri) {
  const parts = uri.substring('ss://'.length).split('#');
  const remark = decodeURIComponent(parts[1] || 'Shadowsocks');
  const corePart = parts[0];
  
  const pluginMatch = corePart.match(/@(.+?)\/\?plugin=(.*)/);
  let userServerPort, pluginData = {};
  let pluginExists = false;

  if (pluginMatch) {
      const userInfoBase64 = corePart.substring(0, pluginMatch.index);
      userServerPort = atob(userInfoBase64);
      
      const pluginRaw = tryUrlDecode(pluginMatch[2]);
      
      const params = pluginRaw.split(';');
      params.forEach(param => {
          if (param === 'tls') pluginData.security = 'tls';
          else if (param.startsWith('host=')) pluginData.host = param.substring(5);
          else if (param.startsWith('path=')) pluginData.path = param.substring(5);
      });
      pluginData.plugin = 'v2ray-plugin';
      pluginExists = true;
  } else {
      userServerPort = atob(corePart);
  }

  const [userInfo, serverPort] = userServerPort.split('@');
  const [method, password] = userInfo.split(':');
  const [server, port] = serverPort.split(':');

  return {
    protocol: 'ss',
    remark: remark,
    server: server,
    port: parseInt(port, 10),
    password: password,
    method: method,
    network: pluginExists ? 'ws' : 'tcp', 
    plugin: pluginData.plugin,
    security: pluginData.security || 'none',
    sni: pluginData.host || server,
    host: pluginData.host || server,
    path: pluginData.path || '/',
    serviceName: '',
  };
}

// General function to map fields for generators
function mapFields(d) {
  const pass = d.password;
  
  return {
    protocol: d.protocol,
    remark: d.remark,
    server: d.server,
    port: d.port,
    password: pass, 
    uuid: d.protocol === 'vless' || d.protocol === 'vmess' ? pass : undefined, 
    alterId: d.alterId, 
    method: d.method, 
    network: d.network,
    security: d.security,
    sni: d.sni,
    host: d.host,
    path: d.path,
    plugin: d.plugin,
    serviceName: d.serviceName,
  };
}

// =========================================================================
// --- Clash Meta Generator (Multi-Proxy) - MENGGUNAKAN TEMPLATE LENGKAP clash.js ---
// =========================================================================
function generateClashMetaProxies(fieldsList) {
    let proxyConfigs = [];
    let proxyNames = []; // Digunakan untuk mengisi grup BEST-PING

    for (const fields of fieldsList) {
        let transportOpts = '';

        if (fields.network === 'ws') {
            transportOpts = `  ws-opts:
    path: ${fields.path}
    headers:
      Host: ${fields.host}`;
        } else if (fields.network === 'grpc') {
            transportOpts = `  grpc-opts:
    grpc-service-name: ${fields.serviceName || ''}`;
        }

        let proxy = '';
        // Ubah format penamaan untuk keamanan dan konsistensi di YAML
        const safeRemark = fields.remark.replace(/[^\w\s-]/g, '_').trim(); 
        
        if (fields.protocol === 'vless' || fields.protocol === 'vmess') {
            proxy =
`- name: ${safeRemark}
  server: ${fields.server}
  port: ${fields.port}
  type: ${fields.protocol}
  ${fields.protocol === 'vless' ? `uuid: ${fields.uuid}` : `uuid: ${fields.uuid}\n  alterId: ${fields.alterId}`}
  cipher: auto
  tls: ${fields.security === 'tls'}
  udp: true
  skip-cert-verify: true
  network: ${fields.network}
  servername: ${fields.sni}
${transportOpts}`;
        } else if (fields.protocol === 'trojan') {
            proxy = 
`- name: ${safeRemark}
  server: ${fields.server}
  port: ${fields.port}
  type: trojan
  password: ${fields.password}
  network: ${fields.network}
  tls: ${fields.security === 'tls'}
  skip-cert-verify: true
  servername: ${fields.sni}
${transportOpts}`;
        } else if (fields.protocol === 'ss') {
            proxy = 
`- name: ${safeRemark}
  server: ${fields.server}
  port: ${fields.port}
  type: ss
  cipher: ${fields.method}
  password: ${fields.password}
  plugin: ${fields.plugin || 'v2ray-plugin'}
  plugin-opts:
    mode: websocket
    host: ${fields.host}
    path: ${fields.path}
    tls: ${fields.security === 'tls'}
    skip-cert-verify: true
    servername: ${fields.sni}`;
        } else {
            proxy = `# Error: Protokol ${fields.protocol} tidak didukung oleh Clash Meta.`;
        }
        
        proxyConfigs.push(proxy);
        proxyNames.push(`  - ${safeRemark}`); // Tambahkan nama proxy ke daftar untuk BEST-PING
    }

    const proxyListJoined = proxyConfigs.join('\n');
    const proxyNamesJoined = proxyNames.join('\n');
    
    // TEMPLATE clash.js
    const template = `port: 7890
socks-port: 7891
redir-port: 7892
mixed-port: 7893
tproxy-port: 7895
ipv6: false
mode: rule
log-level: silent
allow-lan: true
external-controller: 0.0.0.0:9090
secret: ""
bind-address: "*"
unified-delay: true
profile:
  store-selected: true
  store-fake-ip: true
dns:
  enable: true
  ipv6: false
  use-host: true
  enhanced-mode: fake-ip
  listen: 0.0.0.0:7874
  proxy-server-nameserver:
    - 112.215.203.246
    - 112.215.203.247
    - 112.215.203.248
    - 112.215.203.254
    - 112.215.198.248
    - 112.215.198.254
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
    - 1.0.0.1
  fallback:
    - 9.9.9.9
    - 149.112.112.112
    - 208.67.222.222
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.localdomain"
    - "*.example"
    - "*.invalid"
    - "*.localhost"
    - "*.test"
    - "*.local"
    - "*.home.arpa"
    - time.*.com
    - time.*.gov
    - time.*.edu.cn
    - time.*.apple.com
    - time1.*.com
    - time2.*.com
    - time3.*.com
    - time4.*.com
    - time5.*.com
    - time6.*.com
    - time7.*.com
    - ntp.*.com
    - ntp1.*.com
    - ntp2.*.com
    - ntp3.*.com
    - ntp4.*.com
    - ntp5.*.com
    - ntp6.*.com
    - ntp7.*.com
    - "*.time.edu.cn"
    - "*.ntp.org.cn"
    - +.pool.ntp.org
    - time1.cloud.tencent.com
    - music.163.com
    - "*.music.163.com"
    - "*.126.net"
    - musicapi.taihe.com
    - music.taihe.com
    - songsearch.kugou.com
    - trackercdn.kugou.com
    - "*.kuwo.cn"
    - api-jooxtt.sanook.com
    - api.joox.com
    - joox.com
    - y.qq.com
    - "*.y.qq.com"
    - streamoc.music.tc.qq.com
    - mobileoc.music.tc.qq.com
    - isure.stream.qqmusic.qq.com
    - dl.stream.qqmusic.qq.com
    - aqqmusic.tc.qq.com
    - amobile.music.tc.qq.com
    - "*.xiami.com"
    - "*.music.migu.cn"
    - music.migu.cn
    - "*.msftconnecttest.com"
    - "*.msftncsi.com"
    - msftconnecttest.com
    - msftncsi.com
    - localhost.ptlogin2.qq.com
    - localhost.sec.qq.com
    - +.srv.nintendo.net
    - +.stun.playstation.net
    - xbox.*.microsoft.com
    - xnotify.xboxlive.com
    - +.battlenet.com.cn
    - +.wotgame.cn
    - +.wggames.cn
    - +.wowsgame.cn
    - +.wargaming.net
    - proxy.golang.org
    - stun.*.*
    - stun.*.*.*
    - +.stun.*.*
    - +.stun.*.*.*
    - +.stun.*.*.*.*
    - heartbeat.belkin.com
    - "*.linksys.com"
    - "*.linksyssmartwifi.com"
    - "*.router.asus.com"
    - mesu.apple.com
    - swscan.apple.com
    - swquery.apple.com
    - swdownload.apple.com
    - swcdn.apple.com
    - swdist.apple.com
    - lens.l.google.com
    - stun.l.google.com
    - +.nflxvideo.net
    - "*.square-enix.com"
    - "*.finalfantasyxiv.com"
    - "*.ffxiv.com"
    - "*.mcdn.bilivideo.cn"
    - +.media.dssott.com
proxies:
${proxyNamesJoined}

proxy-groups:
- name: INTERNET
  type: select
  disable-udp: false
  proxies:
    - DIRECT
    - REJECT
    - BEST-PING
  url: http://www.gstatic.com/generate_204
  interval: 120

- name: BEST-PING
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 120
  proxies:
    - DIRECT
    - REJECT
${proxyNamesJoined}

rule-providers:
  rule_hijacking:
    type: file
    behavior: classical
    path: ./rule_provider/rule_hijacking.yaml
    url: https://raw.githubusercontent.com/malikshi/open_clash/main/rule_provider/rule_hijacking.yaml
  rule_privacy:
    type: file
    behavior: classical
    url: https://raw.githubusercontent.com/malikshi/open_clash/main/rule_provider/rule_privacy.yaml
    path: ./rule_provider/rule_privacy.yaml
  rule_basicads:
    type: file
    behavior: domain
    url: https://raw.githubusercontent.com/malikshi/open_clash/main/rule_provider/rule_basicads.yaml
    path: ./rule_provider/rule_basicads.yaml
  rule_personalads:
    type: file
    behavior: classical
    url: https://raw.githubusercontent.com/malikshi/open_clash/main/rule_provider/rule_personalads.yaml
    path: ./rule_provider/rule_personalads.yaml

rules:
- IP-CIDR,198.18.0.1/16,REJECT,no-resolve
- RULE-SET,rule_personalads,REJECT  # Langsung REJECT untuk memblokir iklan
- RULE-SET,rule_basicads,REJECT     # Langsung REJECT untuk memblokir iklan
- RULE-SET,rule_hijacking,REJECT    # Langsung REJECT untuk memblokir
- RULE-SET,rule_privacy,REJECT      # Langsung REJECT untuk memblokir
- MATCH,INTERNET`;

    return template;
}

// =========================================================================
// --- Clash Provider Generator (Proxies Only) - DENGAN INDENTASI 2 SPASI ---
// =========================================================================
function generateClashProviderProxies(fieldsList) {
    let proxyConfigs = [];

    for (const fields of fieldsList) {
        let transportOpts = '';

        // Indentasi untuk ws-opts/grpc-opts harus ditambah 2 spasi dari indentasi proxy utamanya.
        if (fields.network === 'ws') {
            transportOpts = `    ws-opts:
      path: ${fields.path}
      headers:
        Host: ${fields.host}`;
        } else if (fields.network === 'grpc') {
            transportOpts = `    grpc-opts:
      grpc-service-name: ${fields.serviceName || ''}`;
        }

        let proxy = '';
        // Ubah format penamaan untuk keamanan dan konsistensi di YAML
        const safeRemark = fields.remark.replace(/[^\w\s-]/g, '_').trim(); 
        
        // Setiap proxy dimulai dengan dua spasi
        if (fields.protocol === 'vless' || fields.protocol === 'vmess') {
            proxy =
`  - name: ${safeRemark}
    server: ${fields.server}
    port: ${fields.port}
    type: ${fields.protocol}
    ${fields.protocol === 'vless' ? `uuid: ${fields.uuid}` : `uuid: ${fields.uuid}\n    alterId: ${fields.alterId}`}
    cipher: auto
    tls: ${fields.security === 'tls'}
    udp: true
    skip-cert-verify: true
    network: ${fields.network}
    servername: ${fields.sni}
${transportOpts}`;
        } else if (fields.protocol === 'trojan') {
            proxy = 
`  - name: ${safeRemark}
    server: ${fields.server}
    port: ${fields.port}
    type: trojan
    password: ${fields.password}
    network: ${fields.network}
    tls: ${fields.security === 'tls'}
    skip-cert-verify: true
    servername: ${fields.sni}
${transportOpts}`;
        } else if (fields.protocol === 'ss') {
            // Indentasi plugin-opts juga harus disesuaikan
            proxy = 
`  - name: ${safeRemark}
    server: ${fields.server}
    port: ${fields.port}
    type: ss
    cipher: ${fields.method}
    password: ${fields.password}
    plugin: ${fields.plugin || 'v2ray-plugin'}
    plugin-opts:
      mode: websocket
      host: ${fields.host}
      path: ${fields.path}
      tls: ${fields.security === 'tls'}
      skip-cert-verify: true
      servername: ${fields.sni}`;
        } else {
            proxy = `  # Error: Protokol ${fields.protocol} tidak didukung oleh Clash Meta.`;
        }
        
        proxyConfigs.push(proxy);
    }
    
    const proxyListJoined = proxyConfigs.join('\n');
    
    // Prefix 'proxies:' tanpa indentasi
    return `proxies:\n${proxyListJoined}`;
}

// Master converter function
function convertLink(linksInput, format) {
    const linkArray = linksInput.split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0 && (line.startsWith('vless://') || line.startsWith('vmess://') || line.startsWith('trojan://') || line.startsWith('ss://')));
    
    if (linkArray.length === 0) {
        return '❌ Gagal: Tidak ada link VLESS, VMess, Trojan, atau Shadowsocks yang valid ditemukan.';
    }

    const successfulConversions = [];
    
    for (const link of linkArray) {
        try {
            let d;
            const decodedLink = tryUrlDecode(link);

            if (decodedLink.startsWith('vless://')) d = parseVlessUri(decodedLink);
            else if (decodedLink.startsWith('vmess://')) d = parseVmessUri(decodedLink);
            else if (decodedLink.startsWith('trojan://')) d = parseTrojanUri(decodedLink);
            else if (decodedLink.startsWith('ss://')) d = parseShadowsocksUri(decodedLink);
            else continue;
            
            successfulConversions.push(mapFields(d));
            
        } catch (e) {
            console.error(`Error parsing link: ${link}`, e);
        }
    }
    
    if (successfulConversions.length === 0) {
        return '❌ Gagal: Semua link yang dimasukkan tidak valid atau gagal di-parse.';
    }

    if (format === 'clash') return generateClashMetaProxies(successfulConversions);
    if (format === 'clash-provider') return generateClashProviderProxies(successfulConversions);
    
    return 'Format konversi tidak valid.';
}

// ---------- FETCH PROXY LIST ----------
async function getProxyList(proxyBankUrl) {
  const url = proxyBankUrl || "https://raw.githubusercontent.com/AFRcloud/ProxyList/refs/heads/main/ProxyList.txt";
  const res = await fetch(url);
  if (res.status !== 200) return [];
  const text = await res.text();
  return text.split("\n")
    .filter(Boolean)
    .map(line => {
      const [proxyIP, proxyPort, country, org] = line.split(",");
      return { proxyIP: proxyIP || "Unknown", proxyPort: proxyPort || "443", country: country || "XX", org: org || "Unknown Org" };
    });
}

// ---------- FLAG EMOJI ----------
function getFlagEmoji(cc) {
  // Hanya proses jika cc valid dan 2 karakter
  if (!cc || typeof cc !== 'string' || cc.length < 2) return '';
  return cc.toUpperCase()
    .split("")
    .map(c => String.fromCodePoint(127397 + c.charCodeAt(0)))
    .join("");
}

// --- FUNGSI UTILITY BARU UNTUK MERENDER KONTEN SAJA (JSON Response) ---

/**
 * Membangun Header dengan judul halaman (rata kiri, putih).
 * Tombol Hamburger/Drawer telah dihapus.
 * @param {string} title - Judul halaman yang akan ditampilkan di header.
 * @param {string} iconHtml - HTML untuk ikon yang akan ditampilkan di sebelah judul.
 */
function buildNavButtonsSPA(title, iconHtml) {
    // Tombol Hamburger telah dihapus
    return `
        <header id="app-header" class="w-full max-w-7xl flex justify-start items-center px-2 sm:px-3 py-2 bg-gray-800 rounded-b-lg shadow-xl border-b border-gray-700" style="box-shadow: 0 4px 10px rgba(0,0,0,0.5);">
            
            <div class="header-title-style">
                ${iconHtml}<span>${title}</span>
            </div>
            
            <div class="ml-auto flex gap-3 text-sm font-medium">
                <a href="/vpn/0" onclick="navigateTo('/vpn/0'); return false;" class="text-gray-400 hover:text-accent-blue transition-colors duration-200" title="Create VPN"><i class="fas fa-satellite-dish"></i></a>
                <a href="/converter" onclick="navigateTo('/converter'); return false;" class="text-gray-400 hover:text-accent-blue transition-colors duration-200" title="Converter"><i class="fas fa-exchange-alt"></i></a>
                <a href="/cek-kuota" onclick="navigateTo('/cek-kuota'); return false;" class="text-gray-400 hover:text-accent-blue transition-colors duration-200" title="Cek Kuota"><i class="fas fa-signal"></i></a>
                <a href="/my-ip" onclick="navigateTo('/my-ip'); return false;" class="text-gray-400 hover:text-accent-blue transition-colors duration-200" title="Cek MyIP"><i class="fas fa-map-marker-alt"></i></a>
            </div>
        </header>
    `;
}

/**
 * Hanya menghasilkan konten HTML dan metadata untuk /vpn (tanpa wrapper)
 */
async function buildHTMLTableContentOnly(proxyList, pageIndex, selectedProtocol, selectedCountry, selectedWildcard, selectedSecurity) {
    let filtered = proxyList;
    if (selectedCountry && selectedCountry !== "ALL") {
        filtered = filtered.filter(p => p.country.toUpperCase() === selectedCountry.toUpperCase());
    }

    const totalProxies = filtered.length;
    const totalPages = Math.max(1, Math.ceil(totalProxies / PROXY_PER_PAGE)); 
    const currentPage = pageIndex + 1;

    const start = pageIndex * PROXY_PER_PAGE;
    const end = start + PROXY_PER_PAGE;
    const pageProxies = filtered.slice(start, end);
    const uuid = `eeeeeee3-eeee-4eee-aeee-eeeeeeeeeee5`;

    const serverAddress = selectedWildcard || APP_DOMAIN;
    const fullHost = selectedWildcard ? `${selectedWildcard}.${APP_DOMAIN}` : APP_DOMAIN;
    
    const port = selectedSecurity === "tls" ? "443" : "80";

    let rows = "";
    for (let i = 0; i < pageProxies.length; i++) {
        const p = pageProxies[i];
        const rowNumber = start + i + 1;

        const path = `/${p.proxyIP}-${p.proxyPort}`;
        let config = "";
        if (selectedProtocol === "vless") {
            config = `vless://${uuid}@${serverAddress}:${port}?encryption=none&type=ws&host=${fullHost}&path=${path}${selectedSecurity === "tls" ? "&security=tls&sni=" + fullHost : ""}#${p.country}+${p.org}`;
        } else if (selectedProtocol === "trojan") {
            config = `trojan://${uuid}@${serverAddress}:${port}?type=ws&host=${fullHost}&path=${path}${selectedSecurity === "tls" ? "&security=tls&sni=" + fullHost : ""}#${p.country}+${p.org}`;
        } else if (selectedProtocol === "ss") {
            const userinfo = btoa(`none:${uuid}`);
            const plugin = `v2ray-plugin;${selectedSecurity === "tls" ? "tls;" : ""}host=${fullHost};path=${path}`;
            config = `ss://${userinfo}@${serverAddress}:${port}?plugin=${encodeURIComponent(plugin)}#${p.country}+${p.org}`;
        }

        // Mengganti text-sm menjadi text-base untuk memperbesar font data tabel
        rows += `
          <tr class="border-t border-gray-700 hover:bg-gray-800">
            <td class="px-2 py-2 text-base text-gray-400">${rowNumber}</td>
            <td class="px-2 py-2 text-base font-mono">${p.proxyIP}</td>
            <td class="px-2 py-2 text-base">${getFlagEmoji(p.country)} ${p.country}</td>
            <td class="px-2 py-2 text-base truncate max-w-[100px]">${p.org}</td>
            <td class="px-2 py-2">
              <button onclick="copyToClipboard('${config}', this)" class="text-white px-3 py-1 rounded text-xs font-semibold transition-colors duration-200 action-btn">Copy</button>
            </td>
          </tr>
        `;
    }

    const uniqueCountries = [...new Set(proxyList.map(p => p.country.toUpperCase()))].sort();
    const countryOptions = uniqueCountries.map(cc =>
        `<option value="${cc}" ${cc === selectedCountry ? "selected" : ""}>${getFlagEmoji(cc)} ${cc}</option>`
    ).join("");

    const protocolOptions = PROTOCOLS.map(p =>
        `<option value="${p}" ${p === selectedProtocol ? "selected" : ""}>${p.toUpperCase()}</option>`
    ).join("");

    const wildcardOptions = [
        "ava.game.naver.com",
        "df.game.naver.com",
        "care.pmang.game.naver.com",
        "plus-store.naver.com",
        "quiz.int.vidio.com",
        "ads.ruangguru.com",
        "support.zoom.us",
        "source.zoom.us",
        "api.midtrans.com",
        "chat.sociomile.com",
        "blog.sushiroll.co.id",
        "investors.spotify.com",
        "graph.instagram.com",
        "api24-normal-alisg.tiktokv.com",
    ].map(d =>
        `<option value="${d}" ${d === selectedWildcard ? "selected" : ""}>${d}</option>`
    ).join("");
    
    const securityOptions = [
        { value: "tls", label: "TLS (443)" },
        { value: "ntls", label: "NTLS (80)" },
    ].map(s =>
        `<option value="${s.value}" ${s.value === selectedSecurity ? "selected" : ""}>${s.label}</option>`
    ).join("");

    const table = `
        <div class="overflow-x-auto w-full max-w-full">
            <table class="min-w-full table-dark bg-gray-800 border border-gray-700 rounded-lg text-base overflow-hidden" style="box-shadow: 0 4px 10px rgba(0,0,0,0.3);">
                <thead>
                    <tr class="text-gray-400">
                        <th class="px-2 py-2 text-left">No.</th>
                        <th class="px-2 py-2 text-left">IP</th>
                        <th class="px-2 py-2 text-left">Country</th>
                        <th class="px-2 py-2 text-left">ISP</th>
                        <th class="px-2 py-2 text-left">Action</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `;

    // Mengganti text-xs (label) menjadi text-sm dan text-sm (select) menjadi text-base
    const filterSection = `
        <div class="w-full max-w-5xl mb-3 p-3 bg-gray-800 rounded-lg shadow-xl grid grid-cols-2 md:grid-cols-4 gap-2" style="box-shadow: 0 4px 15px rgba(0,0,0,0.5), inset 0 0 10px rgba(0,0,0,0.2);">
            <div>
                <label for="protocol" class="block font-medium mb-1 text-gray-300 text-sm">Protocol</label>
                <select id="protocol" onchange="updateFilters()" class="w-full px-2 py-1 rounded-md input-dark text-base focus:ring-2">
                    ${protocolOptions}
                </select>
            </div>
            <div>
                <label for="country" class="block font-medium mb-1 text-gray-300 text-sm">Country</label>
                <select id="country" onchange="updateFilters()" class="w-full px-2 py-1 rounded-md input-dark text-base focus:ring-2">
                    <option value="ALL">🌍 All</option>
                    ${countryOptions}
                </select>
            </div>
            <div>
                <label for="wildcard" class="block font-medium mb-1 text-gray-300 text-sm">Wildcard/Host</label>
                <select id="wildcard" onchange="updateFilters()" class="w-full px-2 py-1 rounded-md input-dark text-base focus:ring-2">
                    <option value="">📝 Default (${APP_DOMAIN})</option>
                    ${wildcardOptions}
                </select>
            </div>
            <div>
                <label for="security" class="block font-medium mb-1 text-gray-300 text-sm">Security/Port</label>
                <select id="security" onchange="updateFilters()" class="w-full px-2 py-1 rounded-md input-dark text-base focus:ring-2">
                    ${securityOptions}
                </select>
            </div>
        </div>
    `;

    const pagination = `
        <nav class="w-full max-w-6xl mt-3 flex flex-col items-center gap-2">
            <div class="text-center text-xs font-semibold text-gray-400 mb-1">
                Page ${currentPage} of ${totalPages} (${totalProxies} Proxies Total)
            </div>
            <div class="flex justify-center gap-3">
                <button ${pageIndex === 0 ? "disabled" : ""}
                    onclick="navigateTo('/vpn/${pageIndex - 1}?protocol=${selectedProtocol}&country=${selectedCountry}&wildcard=${encodeURIComponent(selectedWildcard)}&security=${selectedSecurity}')"
                    class="px-4 py-1 text-white rounded-md disabled:opacity-50 text-sm font-semibold btn-gradient hover:opacity-80 transition-opacity">
                    <i class="fa fa-chevron-left"></i> Prev
                </button>
                <button ${currentPage >= totalPages ? "disabled" : ""}
                    onclick="navigateTo('/vpn/${pageIndex + 1}?protocol=${selectedProtocol}&country=${selectedCountry}&wildcard=${encodeURIComponent(selectedWildcard)}&security=${selectedSecurity}')"
                    class="px-4 py-1 text-white rounded-md disabled:opacity-50 text-sm font-semibold btn-gradient hover:opacity-80 transition-opacity">
                    Next <i class="fa fa-chevron-right"></i>
                </button>
            </div>
        </nav>
    `;

    const content = `
        <div id="slide-1" class="slide w-full main-container">
            ${filterSection}
            ${table}
            ${pagination}
        </div>
    `;

    const extraScript = `
        function updateFilters() {
            const p = document.getElementById("protocol").value;
            const c = document.getElementById("country").value;
            const w = document.getElementById("wildcard").value;
            const s = document.getElementById("security").value;
            // Gunakan navigateTo SPA
            navigateTo('/vpn/0?protocol=' + p + '&country=' + c + '&wildcard=' + encodeURIComponent(w) + '&security=' + s);
        }
    `;

    return { content, extraScript, icon: '<i class="fas fa-satellite-dish"></i>' };
}

/**
 * Hanya menghasilkan konten HTML dan metadata untuk /converter (tanpa wrapper)
 */
function buildConverterHTMLContentOnly() {
    const formatOptions = [
        { value: "clash", label: "Clash Meta (Full Config)" },
        { value: "clash-provider", label: "Clash Provider (Proxies Only)" },
    ].map(f => `<option value="${f.value}">${f.label}</option>`).join("");

    const content = `
        <div id="slide-2" class="slide w-full max-w-xl main-container">
            <div class="input-group mb-3 p-3">
                <label for="link-input" class="block font-medium mb-1 text-gray-300 text-sm">Masukkan Link:</label>
                <textarea id="link-input" rows="4" class="w-full px-3 py-2 rounded-md input-dark border-transparent focus:ring-2 focus:ring-[#66b5e8] resize-none font-mono text-sm" placeholder="vless://.... vmess://.... trojan://... "></textarea>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-2 mb-4">
                <div class="md:col-span-2">
                    <label for="format-select" class="block font-medium mb-1 text-gray-300 text-sm">Pilih Format Output:</label>
                    <select id="format-select" class="w-full px-3 py-2 rounded-md input-dark text-sm focus:ring-2 focus:ring-[#66b5e8]">
                        ${formatOptions}
                    </select>
                </div>
                <div class="md:col-span-1">
                    <button id="convert-button" class="w-full h-full py-2 rounded-md text-white font-bold text-sm btn-gradient hover:opacity-90 transition-opacity mt-0 md:mt-[23px]">
                        <i class="fa fa-arrow-right-arrow-left mr-1"></i> Convert
                    </button>
                </div>
            </div>
            
            <div id="converter-result" class="input-group p-3">
                <label class="block font-medium mb-1 text-gray-300 text-sm">Hasil Config:</label>
                <textarea id="result-output" rows="10" class="w-full px-3 py-2 rounded-md input-dark border-transparent focus:ring-2 focus:ring-[#66b5e8] resize-none font-mono text-xs" readonly placeholder="Output konfigurasi akan muncul di sini (YAML/JSON)."></textarea>
            </div>
            <div class="mt-3 text-center flex justify-center gap-2">
                <button onclick="copyToClipboard(document.getElementById('result-output').value, this)" class="px-4 py-1.5 text-white rounded-md text-sm font-semibold action-btn">
                    <i class="fa fa-copy mr-1"></i> Salin Config
                </button>
                <button onclick="downloadConfig()" class="px-4 py-1.5 text-white rounded-md text-sm font-semibold action-btn">
                    <i class="fa fa-download mr-1"></i> Download
                </button>
            </div>
        </div>
    `;

    const extraScript = `
        document.getElementById('convert-button').addEventListener('click', function() {
            const linkInput = document.getElementById('link-input').value;
            const format = document.getElementById('format-select').value;
            const resultOutput = document.getElementById('result-output');

            if (!linkInput.trim()) {
                console.error('Link tidak boleh kosong.');
                resultOutput.value = '❌ Gagal: Link tidak boleh kosong.';
                return;
            }

            const converted = convertLink(linkInput, format);
            
            if (converted.startsWith('❌ Gagal:') || converted.startsWith('Error:')) {
                resultOutput.value = converted;
            } else {
                resultOutput.value = converted;
            }
        });
    `;

    return { content, extraScript, icon: '<i class="fas fa-exchange-alt"></i>' };
}

/**
 * Hanya menghasilkan konten HTML dan metadata untuk /cek-kuota (tanpa wrapper)
 */
function buildCekKuotaHTMLContentOnly() {
    const content = `
        <div class="w-full max-w-sm mx-auto main-container">
            <div class="bg-gray-800 p-3 rounded-lg mb-3 text-center text-gray-400 border border-gray-700 shadow-md" style="box-shadow: 0 2px 5px rgba(0,0,0,0.5), inset 0 0 10px rgba(0,0,0,0.2);">
                <i class="fa fa-info-circle text-accent-blue mr-1"></i> Gunakan layanan ini secara bijak dan hindari spam.
            </div>
            
            <form id="formnya" class="p-3 bg-gray-800 rounded-lg shadow-xl border border-gray-700" style="box-shadow: 0 4px 15px rgba(0,0,0,0.5), inset 0 0 10px rgba(0,0,0,0.2);">
                <div class="mb-3">
                    <label for="msisdn" class="block font-medium mb-1 text-gray-300 text-sm">Nomor HP XL/AXIS:</label>
                    <input type="number" class="w-full px-3 py-2 rounded-md input-dark text-base focus:ring-2 focus:ring-accent-blue" id="msisdn" placeholder="08xxx / 628xxx" maxlength="16" required>
                </div>
                <button type="button" id="submitCekKuota" class="w-full py-2 rounded-md text-white font-bold text-sm btn-gradient hover:opacity-90 transition-opacity">
                    <i class="fa fa-search mr-1"></i>Cek Sekarang
                </button>
            </form>

            <div id="hasilnya" class="mt-3"></div>
        </div>
    `;

    // Skrip JQuery harus didefinisikan di sini agar dapat dievaluasi setelah elemen dimuat oleh SPA
    const extraScript = `
        function cekKuota() {
            const msisdn = document.getElementById('msisdn').value;
            if (!msisdn) {
                console.error('Nomor tidak boleh kosong.');
                return;
            }
            
            $('#cover-spin').show();
            $.ajax({
                type: 'GET',
                url: \`https://apigw.kmsp-store.com/sidompul/v4/cek_kuota?msisdn=\${msisdn}&isJSON=true\`,
                dataType: 'JSON',
                contentType: 'application/x-www-form-urlencoded',
                beforeSend: function (req) {
                    req.setRequestHeader('Authorization', 'Basic c2lkb21wdWxhcGk6YXBpZ3drbXNw');
                    req.setRequestHeader('X-API-Key', '60ef29aa-a648-4668-90ae-20951ef90c55');
                    req.setRequestHeader('X-App-Version', '4.0.0');
                },
                success: function (res) {
                    $('#cover-spin').hide();
                    $('#hasilnya').html('');
                    if (res.status) {
                        // MODIFIKASI: Tambahkan style font Courier New
                        $('#hasilnya').html(\`<div class="result-success p-3 rounded-lg mt-3 text-center font-semibold" style="font-family: 'Courier New', monospace;">\${res.data.hasil}</div>\`);
                    } else {
                        console.error('Gagal Cek Kuota: ' + res.message);
                        // MODIFIKASI: Tambahkan style font Courier New
                        $('#hasilnya').html(\`<div class="result-error p-3 rounded-lg mt-3 text-center font-semibold" style="font-family: 'Courier New', monospace;">\${res.data.keteranganError}</div>\`);
                    }
                },
                error: function () {
                    $('#cover-spin').hide();
                    console.error('Terjadi kesalahan koneksi.');
                    // MODIFIKASI: Tambahkan style font Courier New
                    $('#hasilnya').html(\`<div class="result-error p-3 rounded-lg mt-3 text-center font-semibold" style="font-family: 'Courier New', monospace;">Terjadi kesalahan koneksi atau server tidak merespons.</div>\`);
                }
            });
        }
        
        // Pemasangan event listener setelah konten dimuat
        $('#submitCekKuota').off('click').on('click', cekKuota); // Gunakan .off() untuk menghindari duplikasi
        $('#msisdn').off('keypress').on('keypress', function (e) {
            if (e.which === 13) cekKuota();
        });
    `;

    return { content, extraScript, icon: '<i class="fas fa-signal"></i>' };
}

/**
 * Hanya menghasilkan konten HTML dan metadata untuk /my-ip (tanpa wrapper)
 * PERBAIKAN: Menggunakan Promise.race dengan timeout untuk pengambilan data cepat.
 */
function buildCekMyIPHTMLContentOnly() {
    const content = `
        <div class="w-full max-w-lg mx-auto main-container">
            <h2 class="centered-heading text-solid-white mb-4 text-xl">Informasi IP Anda</h2>
            <div class="p-3 bg-gray-800 rounded-lg shadow-xl border border-gray-700" style="box-shadow: 0 4px 15px rgba(0,0,0,0.5), inset 0 0 10px rgba(0,0,0,0.2);">
                <div id="ip-result-loading" class="text-center text-gray-400 font-semibold py-4">
                    <i class="fa fa-spinner fa-spin mr-2"></i> Mencari API tercepat...
                </div>
                <div id="ip-result-data" class="hidden">
                    </div>
            </div>
            <div class="mt-3 text-center">
                <button type="button" onclick="cekMyIP()" id="refreshMyIP" class="px-5 py-2 rounded-md text-white font-bold text-sm btn-gradient hover:opacity-90 transition-opacity">
                    <i class="fa fa-sync-alt mr-1"></i> Refresh IP
                </button>
            </div>
        </div>
    `;

    const extraScript = `
        const IP_API_TIMEOUT_MS = 4000; // Timeout 4 detik per API

        // Daftar API MyIP dengan format respons yang kompatibel (ip-api.com style)
        const ipApis = [
            { url: 'https://ip-api.com/json/?fields=status,message,query,country,countryCode,regionName,city,isp,org,timezone,lat,lon', name: 'ip-api.com' },
            { 
                url: 'https://ipinfo.io/json', 
                name: 'ipinfo.io', 
                map: (data) => ({ 
                    status: data.ip ? 'success' : 'fail', 
                    query: data.ip, 
                    country: data.country_name || data.country || '-', 
                    countryCode: data.country || '-', 
                    regionName: data.region || data.city || '-', 
                    city: data.city || '-', 
                    isp: data.org || data.asn || '-', 
                    org: data.org || data.asn || '-', 
                    timezone: data.timezone || '-', 
                    // Perlu handling untuk ipinfo.io yang locnya berupa string "lat,lon"
                    lat: data.loc?.split(',')[0] || '-', 
                    lon: data.loc?.split(',')[1] || '-' 
                }) 
            },
            { 
                url: 'https://ip.gs/json', 
                name: 'ip.gs', 
                map: (data) => ({ 
                    status: data.ip ? 'success' : 'fail', 
                    query: data.ip, 
                    country: data.country || '-', 
                    countryCode: data.countryCode || '-', 
                    regionName: data.region || data.city || '-', 
                    city: data.city || '-', 
                    isp: data.asn_org || data.asn || '-', 
                    org: data.asn_org || data.asn || '-', 
                    timezone: data.timezone || '-', 
                    lat: data.latitude || '-', 
                    lon: data.longitude || '-' 
                }) 
            }
        ];
        
        // Helper untuk fetch dengan timeout
        function fetchWithTimeout(resource, options = {}) {
            const controller = new AbortController();
            const signal = controller.signal;
            
            const timeout = setTimeout(() => controller.abort(), IP_API_TIMEOUT_MS);

            return fetch(resource, { ...options, signal })
                .finally(() => clearTimeout(timeout));
        }

        async function fetchIpData(api) {
            try {
                const response = await fetchWithTimeout(api.url);
                
                if (!response.ok) {
                    // Jika API merespons tapi status bukan 2xx (misal 403), anggap gagal
                    throw new Error(\`HTTP status \${response.status}\`);
                }
                
                let data = await response.json();
                
                // Lakukan mapping jika ada
                if (api.map) {
                    data = api.map(data);
                }
                
                // Periksa status dan IP yang valid
                if (data.status === 'success' || data.query || data.ip) {
                    // Normalize data.query jika API menggunakan data.ip
                    if (data.ip && !data.query) data.query = data.ip;
                    return { status: 'success', data: data, apiName: api.name };
                }

                return { status: 'fail', message: \`Respons API tidak valid\`, apiName: api.name };

            } catch (error) {
                const message = error.name === 'AbortError' ? 'Timeout' : \`Koneksi gagal: \${error.message}\`;
                return { status: 'fail', message: message, apiName: api.name };
            }
        }

        function displayIPResult(data) {
            let html = '';
            
            if (data.status === 'success') {
                const flagFunc = window.getFlagEmoji || getFlagEmoji;
                
                // --- Kustomisasi Tampilan Country (Nama Negara 🇮🇩) ---
                const countryName = data.country || data.countryCode || '-';
                const countryCode = data.countryCode || data.country || '-';
                // Tampilan Sesuai Permintaan: Nama Negara Bendera
                const countryDisplay = \`\${countryName} \${flagFunc(countryCode)}\`;
                
                // Menggabungkan ISP dan Organization
                const isp = data.isp || '-';
                const org = data.org || '-';
                // Jika ISP dan Org berbeda, tampilkan keduanya. Jika sama, tampilkan salah satu. Jika salah satu kosong, tampilkan yang ada.
                const ispOrg = (isp !== '-' && org !== '-' && isp !== org) ? \`\${isp} / \${org}\` : isp === '-' ? org : isp;

                html = \`
                    <table class="w-full text-left text-sm table-dark">
                        <tbody>
                            <tr><th class="py-2 px-3 border-b border-gray-700">IP Address</th><td class="py-2 px-3 border-b border-gray-700 font-mono text-sm text-accent-blue">\${data.query || '-'}</td></tr>
                            <tr><th class="py-2 px-3 border-b border-gray-700">Country</th><td class="py-2 px-3 border-b border-gray-700 font-semibold">\${countryDisplay}</td></tr>
                            <tr><th class="py-2 px-3 border-b border-gray-700">Region/State</th><td class="py-2 px-3 border-b border-gray-700">\${data.regionName || '-'}</td></tr>
                            <tr><th class="py-2 px-3 border-b border-gray-700">City</th><td class="py-2 px-3 border-b border-gray-700">\${data.city || '-'}</td></tr>
                            <tr><th class="py-2 px-3 border-b border-gray-700">ISP / Organization</th><td class="py-2 px-3 border-b border-gray-700 text-xs">\${ispOrg}</td></tr>
                            <tr><th class="py-2 px-3 border-b border-gray-700">Timezone</th><td class="py-2 px-3 border-b border-gray-700">\${data.timezone || '-'}</td></tr>
                            <tr><th class="py-2 px-3">Location (Lat, Lon)</th><td class="py-2 px-3">\${data.lat || '-'}, \${data.lon || '-'}</td></tr>
                        </tbody>
                    </table>
                    <div class="text-xs text-gray-500 mt-2 text-center">Data diambil dari: \${data.apiName || 'Unknown API'}</div>
                \`;
            } else {
                html = \`<div class="result-error p-3 rounded-lg mt-3 text-center font-semibold">❌ Gagal mendapatkan data IP. Pesan: \${data.message || 'Unknown Error'}.</div>\`;
            }
            $('#ip-result-data').html(html).removeClass('hidden');
            $('#ip-result-loading').addClass('hidden');
        }

        async function cekMyIP() {
            $('#cover-spin').show();
            $('#ip-result-loading').removeClass('hidden').html('<i class="fa fa-spinner fa-spin mr-2"></i> Mencari API tercepat...');
            $('#ip-result-data').addClass('hidden');
            
            const fetchPromises = ipApis.map(fetchIpData);
            
            let successfulResult = null;
            let failureDetails = [];

            // Promise.allSettled akan menunggu semua selesai, atau Anda bisa menggunakan Promise.race
            // Tapi karena kita ingin mencatat kegagalan API lain, Promise.allSettled lebih baik.
            const results = await Promise.allSettled(fetchPromises);
            
            for (const result of results) {
                if (result.status === 'fulfilled' && result.value.status === 'success') {
                    successfulResult = result.value.data;
                    successfulResult.apiName = result.value.apiName; // Tambahkan nama API ke data
                    break; // Ambil yang pertama berhasil dan keluar
                } else if (result.status === 'fulfilled' && result.value.status === 'fail') {
                    failureDetails.push(\`\${result.value.apiName} (\${result.value.message})\`);
                } else if (result.status === 'rejected') {
                    failureDetails.push(\`\${result.reason.apiName || 'Unknown'} (Critical Failure)\`);
                }
            }


            if (successfulResult) {
                displayIPResult(successfulResult);
            } else {
                const finalErrorMsg = \`Semua \${ipApis.length} API gagal merespons. Detail: \${failureDetails.join('; ')}\`;
                displayIPResult({ status: 'fail', message: finalErrorMsg });
            } 
            
            $('#cover-spin').hide();
        }
        
        // Panggil saat konten dimuat
        cekMyIP();
        $('#refreshMyIP').off('click').on('click', cekMyIP);
    `;

    return { content, extraScript, icon: '<i class="fas fa-map-marker-alt"></i>' };
}

// ---------- COMMON HTML TEMPLATE (Wrapper) - Disesuaikan untuk Rapat UI ----------
function buildBaseHTML(title, content, navButtons, extraHead = '', extraScript = '', extraStyle = '') {
  // Nav buttons kini di-render sebagai Header dan akan disuntikkan ke kontainer ini.
  const navContainer = `<div id="nav-buttons-container" class="w-full flex justify-center sticky top-0 z-50">
      ${navButtons}
  </div>`;
  
  // Konten utama container, padding dirapatkan menjadi p-1 sm:p-2
  const mainContentContainer = `<div id="main-content-container" class="flex flex-col items-center p-1 sm:p-2 flex-grow w-full max-w-7xl">
      ${content}
  </div>`;
  
  // Skrip dasar untuk navigasi dan helper salin tanpa notifikasi
  const embeddedFunctions = `
    // Fungsi SPA Navigasi Client-Side
    const mainContentContainer = document.getElementById('main-content-container');
    const navButtonsContainer = document.getElementById('nav-buttons-container');

    // Fungsi drawer menu telah dihapus sesuai permintaan
    
    async function renderContentFromPath(path, pushState = true) {
        // Tidak ada closeDrawer() karena drawer dihapus
        
        // Tampilkan loading spinner
        $('#cover-spin').show();

        if (pushState) {
            history.pushState(null, '', path);
        }
        
        try {
            const url = new URL(path, window.location.origin);
            const response = await fetch(url.toString(), {
                headers: {
                    // Tanda ke Worker bahwa ini adalah permintaan SPA (JSON)
                    'X-Requested-With': 'XMLHttpRequest' 
                }
            });

            if (response.ok) {
                const data = await response.json();
                
                // Hapus script lama
                const oldScript = document.getElementById('slide-script');
                if (oldScript) oldScript.remove();

                // Suntikkan konten baru dan tombol navigasi
                mainContentContainer.innerHTML = data.content;
                
                // Perbarui Header dengan Judul dan Ikon baru
                const newNavButtons = buildNavButtonsSPA(data.title, data.icon);
                navButtonsContainer.innerHTML = newNavButtons; 
                document.title = data.title;
                
                // Jalankan script yang terkait
                if (data.extraScript) {
                    const newScript = document.createElement('script');
                    newScript.id = 'slide-script';
                    newScript.textContent = data.extraScript;
                    document.body.appendChild(newScript);
                }
            } else {
                console.error('Failed to fetch content for SPA. Status:', response.status);
                // Fallback: full refresh jika gagal (opsional)
                // window.location.href = path; 
            }
        } catch (e) {
            console.error('Error during SPA fetch/render:', e);
        } finally {
            // Sembunyikan loading spinner
            $('#cover-spin').hide();
        }
    }
  
    function navigateTo(path, pushState = true) {
      renderContentFromPath(path, pushState);
    }
    
    // Tangani tombol back/forward browser
    window.addEventListener('popstate', (event) => {
        // Saat popstate terjadi, render konten untuk path saat ini tanpa pushState
        navigateTo(window.location.pathname + window.location.search, false);
    });

    // --- Helper Copy & Download (Sama seperti sebelumnya) ---
    function copyToClipboard(text, element) {
      navigator.clipboard.writeText(text).then(() => {
          // Salin berhasil
      }).catch(err => {
          console.error('Failed to copy text: ', err);
          const textarea = document.createElement('textarea');
          textarea.value = text;
          document.body.appendChild(textarea);
          textarea.select();
          document.execCommand('copy');
          document.body.removeChild(textarea);
      });
      
      if (element) {
        element.style.boxShadow = '0 1px 3px rgba(0, 0, 0, 0.5), inset 0 1px 5px rgba(0, 0, 0, 0.6)';
        element.style.transform = 'translateY(1px)';

        setTimeout(() => {
          element.style.boxShadow = ''; 
          element.style.transform = 'translateY(0)';
        }, 300);
      }
    }
  
    function downloadConfig() {
        const configData = document.getElementById('result-output').value;
        const format = document.getElementById('format-select').value;
        
        if (!configData.trim() || configData.startsWith('❌ Gagal:')) {
            console.error('Tidak ada config valid untuk diunduh.');
            return;
        }

        let filename = 'config_mediafairy';
        let mimeType = 'text/plain';

        if (format === 'clash' || format === 'clash-provider') {
            filename += '.yaml';
            mimeType = 'text/yaml';
        } else {
            filename += '.txt';
        }

        const blob = new Blob([configData], { type: mimeType });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
    
    // Inject semua parser dan generator yang terpakai
    const convertLink = ${convertLink.toString()};
    const parseVlessUri = ${parseVlessUri.toString()};
    const parseVmessUri = ${parseVmessUri.toString()};
    const parseTrojanUri = ${parseTrojanUri.toString()};
    const parseShadowsocksUri = ${parseShadowsocksUri.toString()};
    const generateClashMetaProxies = ${generateClashMetaProxies.toString()};
    const generateClashProviderProxies = ${generateClashProviderProxies.toString()};
    const mapFields = ${mapFields.toString()};
    const tryUrlDecode = ${tryUrlDecode.toString()};
    const getFlagEmoji = ${getFlagEmoji.toString()}; // Tambahkan getFlagEmoji
    const buildNavButtonsSPA = ${buildNavButtonsSPA.toString()}; // Include the updated nav builder

    // Initial load setup for SPA nav 
    document.addEventListener('DOMContentLoaded', () => {
        // Judul halaman awal saat DOM dimuat
        const initialTitle = document.title;
        // Tentukan ikon awal berdasarkan URL (default ke /vpn/0)
        let initialIcon = '<i class="fas fa-satellite-dish"></i>'; 
        if (window.location.pathname === '/converter') {
            initialIcon = '<i class="fas fa-exchange-alt"></i>';
        } else if (window.location.pathname === '/cek-kuota') {
            initialIcon = '<i class="fas fa-signal"></i>';
        } else if (window.location.pathname === '/my-ip') {
            initialIcon = '<i class="fas fa-map-marker-alt"></i>';
        }
        document.getElementById('nav-buttons-container').innerHTML = buildNavButtonsSPA(initialTitle, initialIcon);
    });
  `;

  return `
    <!DOCTYPE html>
    <html lang="en" class="dark">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
      <title>${title}</title>
      <script src="https://cdn.tailwindcss.com"></script>
      <script src="https://cdn.jsdelivr.net/npm/js-yaml@4.1.0/dist/js-yaml.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/js/all.min.js"></script>
      <script src="https://code.jquery.com/jquery-3.6.4.min.js"></script>
      ${extraHead}
      <script>
        tailwind.config = { darkMode: 'selector', theme: { extend: {
            colors: {
                'accent-blue': '#66b5e8',
                'accent-purple': '#a466e8',
            }
        } } };
      </script>
      <style>
        /* Custom Styles for Modern/Elegant Look */
        
        /* START: PENINGKATAN EFEK 3D */
        body {
            perspective: 1000px; 
            overflow-x: hidden; /* DITAMBAHKAN: Mencegah scroll horizontal (geser-geser) */
        }
        .main-container {
          background: rgba(30, 41, 59, 0.8); 
          backdrop-filter: blur(8px);
          border-radius: 0.75rem; /* Dirapatkan */
          box-shadow: 
            0 15px 30px rgba(0, 0, 0, 0.7), /* Dirapatkan */
            0 0 10px rgba(102, 181, 232, 0.2) inset, /* Dirapatkan */
            0 0 3px rgba(0, 0, 0, 0.5); /* Dirapatkan */
          border: 1px solid rgba(100, 116, 139, 0.4); 
          padding: 0.75rem; /* Dirapatkan */
          margin-bottom: 0.5rem; /* Dirapatkan */
          transform: translateZ(10px); /* Dirapatkan */
        }
        .btn-gradient {
          background: linear-gradient(to right, var(--tw-color-accent-blue), var(--tw-color-accent-purple));
          box-shadow: 0 3px 8px rgba(0, 0, 0, 0.4), inset 0 1px 1px rgba(255, 255, 255, 0.2), inset 0 -2px 4px rgba(0, 0, 0, 0.3); /* Dirapatkan */
          transition: all 0.2s ease;
        }
        .btn-gradient:hover:not(:disabled) {
          box-shadow: 0 1px 4px rgba(0, 0, 0, 0.4), inset 0 1px 4px rgba(0, 0, 0, 0.4), inset 0 0 8px rgba(102, 181, 232, 0.8); /* Dirapatkan */
          transform: translateY(0.5px); /* Dirapatkan */
        }
        .input-group {
          background-color: rgba(30, 41, 59, 0.6); 
          border-radius: 0.5rem; /* Dirapatkan */
          padding: 0.5rem; /* Dirapatkan */
          border: 1px solid rgba(100, 116, 139, 0.3);
          box-shadow: inset 0 0 3px rgba(0, 0, 0, 0.5); /* Dirapatkan */
        }
        .input-dark, .input-group textarea, .input-group select {
          background-color: #1f2937; 
          color: #ffffff;
          border: 1px solid #475569; 
          border-radius: 0.375rem; /* Dirapatkan */
          box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.6); /* Dirapatkan */
          transition: border-color 0.2s, box-shadow 0.2s;
        }
        .input-dark:focus, .input-group textarea:focus, .input-group select:focus {
          border-color: var(--tw-color-accent-blue);
          box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.6), 0 0 3px var(--tw-color-accent-blue); /* Dirapatkan */
        }
        .action-btn {
            background-color: #1e293b; 
            color: #94a3b8;
            border: 1px solid #475569;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.1); /* Dirapatkan */
            transition: all 0.2s;
        }
        .action-btn:hover {
            background-color: #334155; 
            color: white;
            box-shadow: 0 0.5px 2px rgba(0, 0, 0, 0.5), inset 0 0.5px 4px rgba(0, 0, 0, 0.6); /* Dirapatkan */
            transform: translateY(0.5px); /* Dirapatkan */
        }
        /* END: PENINGKATAN EFEK 3D */


        .table-dark th {
          background-color: #1e293b; 
          color: #94a3b8; 
          font-weight: 600;
        }
        .table-dark td {
          border-color: #334155; 
        }
        .table-dark tr:nth-child(even) {
          background-color: #111827; 
        }
        .table-dark tr:hover {
          background-color: #334155 !important; 
        }
        .centered-heading {
            text-align: center;
            width: 100%;
            font-size: 1.3rem; /* Dirapatkan */
            font-weight: 800; 
            line-height: 1.2;
            padding-bottom: 0.3rem; /* Dirapatkan */
        }
        .nav-btn-center {
            display: flex;
            align-items: center;
            justify-content: center;
            text-align: center; 
            min-height: 30px; /* Dirapatkan */
            padding: 0.4rem 0.8rem; /* Dirapatkan */
            line-height: 1.1; /* Dirapatkan */
            border-radius: 0.5rem; /* Dirapatkan */
        }
        
        /* JUDUL PUTIH SOLID */
        .text-solid-white {
            color: #ffffff; 
            text-shadow: none; 
        }

        /* Gaya Judul di Header (Hanya di Header, Putih, Rata Kiri) */
        .header-title-style {
            font-size: 1rem; /* text-base (Dirapatkan) */
            font-weight: 700; /* font-bold */
            color: #ffffff; /* Solid White */
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            /* Memberikan ruang untuk navigasi cepat di kanan */
            max-width: calc(100% - 180px); 
            display: flex; /* Untuk ikon */
            align-items: center;
            gap: 0.4rem; /* Dirapatkan */
        }
        
        /* --- STYLE BARU UNTUK CEK KUOTA/MYIP RESULT --- */
        .result-success {
          background-color: #1f2937; 
          border: 1px solid #66b5e8; 
          color: #ffffff;
          box-shadow: 0 0 10px rgba(102, 181, 232, 0.4); 
          transition: all 0.3s ease;
        }
        .result-error {
          background-color: #1f2937; 
          border: 1px solid #a466e8; 
          color: #ffffff;
          box-shadow: 0 0 10px rgba(164, 102, 232, 0.4); 
          transition: all 0.3s ease;
        }
        
        /* Loading Spinner */
        #cover-spin {
          position: fixed;
          width: 100%;
          height: 100%;
          background-color: rgba(0,0,0,0.8);
          z-index: 9999;
          display: none;
        }
        .loader {
          position: absolute;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          border: 5px solid #f3f3f3; /* Dirapatkan */
          border-top: 5px solid var(--tw-color-accent-blue); /* Dirapatkan */
          border-radius: 50%;
          width: 40px; /* Dirapatkan */
          height: 40px; /* Dirapatkan */
          animation: spin 2s linear infinite;
        }
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        
        /* Menu Drawer Styles (Dihapus/Dikosongkan) */
        #mobile-menu-drawer, #drawer-overlay {
            display: none !important;
        }
        
        ${extraStyle}
      </style>
    </head>
    <body class="bg-gray-900 text-white min-h-screen flex flex-col items-center">
      <div id="cover-spin"><div class="loader"></div></div>
      <div id="custom-notification"></div> 
      
      ${navContainer}
      ${mainContentContainer}
      
      <footer class="w-full p-2 text-center mt-auto border-t border-gray-800"> <div class="flex items-center justify-center gap-2 text-xs font-medium text-gray-500">
          <span>Technical Support</span>
          <a href="https://t.me/iMediafairy" target="_blank" class="flex items-center gap-1 text-accent-blue hover:text-accent-purple transition-colors duration-200">
            <i class="fab fa-telegram-plane"></i>
            <span>MEDIAFAIRY</span>
          </a>
        </div>
      </footer>

      <script>
        // Memuat semua fungsi dasar
        ${embeddedFunctions}

        ${extraScript}
        
      </script>
    </body>
    </html>
  `;
}

// ---------- MAIN HANDLER (WORKER) - Diubah untuk mode SPA & MPA ----------
export default {
    async fetch(request, env, ctx) {
        try {
            const url = new URL(request.url);
            const hostname = request.headers.get("Host") || APP_DOMAIN;
            
            // Tanda untuk membedakan antara Full Page Load (MPA) dan SPA Navigation (AJAX)
            const isSPA = request.headers.get('X-Requested-With') === 'XMLHttpRequest';

            let content = '';
            let title = 'Mediafairy';
            let extraScript = '';
            let icon = '<i class="fas fa-magic"></i>'; // Default icon
            
            // Dapatkan parameter untuk /vpn/X
            const pageMatch = url.pathname.match(/^\/vpn\/(\d+)$/);
            const pageIndex = parseInt(pageMatch ? pageMatch[1] : "0");
            const selectedProtocol = url.searchParams.get("protocol") || "vless";
            const selectedCountry = url.searchParams.get("country") || "ALL";
            const selectedWildcard = url.searchParams.get("wildcard") || "";
            const selectedSecurity = url.searchParams.get("security") || "tls";
            
            // Tentukan Judul dan Konten
            if (url.pathname.startsWith("/vpn")) {
                if (!PROTOCOLS.includes(selectedProtocol)) {
                    return new Response("Invalid protocol", { status: 400 });
                }

                const proxyList = await getProxyList(env.PROXY_BANK_URL);
                const result = await buildHTMLTableContentOnly(proxyList, pageIndex, selectedProtocol, selectedCountry, selectedWildcard, selectedSecurity);
                content = result.content;
                extraScript = result.extraScript;
                title = "Create VPN"; // Judul khusus untuk header/title
                icon = result.icon;
                
            } else if (url.pathname === "/converter") {
                const result = buildConverterHTMLContentOnly();
                content = result.content;
                extraScript = result.extraScript;
                title = "Link Converter"; // Judul khusus untuk header/title
                icon = result.icon;

            } else if (url.pathname === "/cek-kuota") {
                const result = buildCekKuotaHTMLContentOnly();
                content = result.content;
                extraScript = result.extraScript;
                title = "Cek Kuota XL/AXIS"; // Judul khusus untuk header/title
                icon = result.icon;
                
            } else if (url.pathname === "/my-ip") { // Rute untuk Cek MyIP
                const result = buildCekMyIPHTMLContentOnly();
                content = result.content;
                extraScript = result.extraScript;
                title = "Cek MyIP"; // Judul khusus untuk header/title
                icon = result.icon;

            } else if (url.pathname === "/") {
                // Redirect root path ke /vpn/0
                const targetUrl = `${url.origin}/vpn/0`;
                if (isSPA) {
                    // Jika root diakses via SPA, kirim konten /vpn/0
                    const proxyList = await getProxyList(env.PROXY_BANK_URL);
                    const result = await buildHTMLTableContentOnly(proxyList, 0, "vless", "ALL", "", "tls");
                    content = result.content;
                    extraScript = result.extraScript;
                    title = "Create VPN";
                    icon = result.icon;
                } else {
                    return Response.redirect(targetUrl, 302);
                }
            } else {
                if (isSPA) {
                    // Jika SPA path tidak ditemukan
                    return new Response(JSON.stringify({ content: '<div class="text-xl text-red-500 text-center mt-10">404 - Content Not Found</div>', navButtons: buildNavButtonsSPA("404 Not Found", '<i class="fas fa-exclamation-triangle"></i>'), title: "404 Not Found" }), { headers: { "Content-Type": "application/json;charset=utf-8" } });
                }
                return new Response("Not Found", { status: 404 });
            }

            // --- Logika Respons ---
            const navButtons = buildNavButtonsSPA(title, icon);

            if (isSPA) {
                // Mode SPA: Kirim JSON yang berisi konten slide saja
                return new Response(JSON.stringify({ content, navButtons, title, icon, extraScript }), { 
                    headers: { "Content-Type": "application/json;charset=utf-8" } 
                });
            } else {
                // Mode MPA: Kirim HTML Penuh
                const html = buildBaseHTML(title, content, navButtons, '', extraScript);
                return new Response(html, { headers: { "Content-Type": "text/html;charset=utf-8" } });
            }

        } catch (err) {
            console.error(err);
            return new Response("Error: " + err.message, { status: 500 });
        }
    }
};

