// Data retention: how long each kind of data is kept, the default policy
// and disk guard, a preview of every change before it is saved, archived
// days and restores, and what retention did lately. Every /api/retention
// route is for admins.
// Uses toast, fill, plural and sentence (cases.js) and the ri* helpers
// (risk.js).
'use strict';

const rtState = {
  ov: null, key: '', seq: 0, poll: null, loadedOnce: false,
  tab: 'policies',
  arch: null, archKey: '', archSeq: 0, archPoll: null, selected: new Set(),
  // last_run.started before a run we asked for, to tell when it finished
  awaitRun: null,
  edit: null, guard: null, confirm: null,
  // true while another server is asked for a run (see rtFollowRun)
  asking: false,
};

// ---------- formatting ----------
const RT_ICON = {
  authentication: 'key-round', endpoint: 'monitor', network_traffic: 'network', change: 'square-pen', malware: 'bug',
  filesystem: 'folder', registry: 'layers', network_resolution: 'globe', image_load: 'cpu', script: 'square-terminal',
  inventory: 'list', configuration_check: 'list-checks', alerts: 'bell',
  other: 'box', risk: 'gauge', findings: 'shield-alert', cases: 'briefcase', intel: 'radar', audit: 'scroll-text',
};
const RT_FIELD_NAME = { keep_days: 'Keep', max_size_gb: 'Size cap', compact_after_days: 'Compact after', max_disk_percent: 'Max disk use', min_days: 'Min days' };

// rtBytes prints a size the way OpenSearch counts it (1 GB = 1024³ bytes).
function rtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}
const rtDays = (n) => plural(n, 'day');
const rtGB = (v) => `${Number(v).toLocaleString(undefined, { maximumFractionDigits: 2 })} GB`;
// rtDay prints a YYYY-MM-DD day (a UTC day, as index names use), with the
// year only when it is not this year.
function rtDay(ds, withYear) {
  const d = new Date(ds + 'T00:00:00Z');
  if (isNaN(d)) return ds;
  const opts = { month: 'short', day: 'numeric', timeZone: 'UTC' };
  if (withYear || d.getUTCFullYear() !== new Date().getUTCFullYear()) opts.year = 'numeric';
  return d.toLocaleDateString(undefined, opts);
}
function rtRange(days) {
  const sorted = [...days].sort();
  const a = sorted[0];
  const b = sorted[sorted.length - 1];
  return a === b ? rtDay(a) : `${rtDay(a)} to ${rtDay(b)}`;
}
const rtDash = () => el('span', { class: 'subtle' }, el('span', { 'aria-hidden': 'true' }, '–'), el('span', { class: 'sr-only' }, 'None'));
// rtCount prints a count in words past a million ("432 billion"), so it
// never reads like a size in bytes.
function rtCount(n) {
  n = Number(n) || 0;
  const big = [[1e12, 'trillion'], [1e9, 'billion'], [1e6, 'million']].find(([v]) => n >= v);
  if (!big) return n.toLocaleString();
  const v = n / big[0];
  return `${v.toLocaleString(undefined, { maximumFractionDigits: v < 10 ? 1 : 0 })} ${big[1]}`;
}
function rtNoun(id, n) {
  const nouns = { findings: ['finding', 'findings'], cases: ['investigation', 'investigations'], intel: ['indicator', 'indicators'], audit: ['record', 'records'] };
  const [one, many] = nouns[id] || ['event', 'events'];
  return `${rtCount(n)} ${n === 1 ? one : many}`;
}
// rtDates writes the server's YYYY-MM-DD days the way the page does.
const rtDates = (t) => String(t == null ? '' : t).replace(/\b(\d{4}-\d{2}-\d{2})\b/g, (_, d) => rtDay(d));
// rtSentence is sentence() for server text: it leaves an index name or
// setting name at the start as it is ("signalith-endpoint-2026.07.05: ...").
function rtSentence(msg) {
  let m = rtDates(String(msg || 'Something went wrong').trim());
  const first = m.split(/[\s:;,]/)[0];
  if (!/[-_./\\\d]/.test(first)) m = m.charAt(0).toUpperCase() + m.slice(1);
  return /[.!?]$/.test(m) ? m : m + '.';
}
// rtFix turns a server problem ("compact_after_days must be ...") into
// the page's words ("Compact after must be ...").
function rtFix(msg) {
  let m = String(msg || '');
  for (const [k, v] of Object.entries(RT_FIELD_NAME)) m = m.split(k).join(v);
  return rtSentence(m);
}
function rtPolicyText(p) {
  return [
    p.keep_days ? `Keep ${rtDays(p.keep_days)}` : 'Keep forever',
    p.max_size_gb ? `${rtGB(p.max_size_gb)} size cap` : 'no size cap',
    p.compact_after_days ? `compact after ${rtDays(p.compact_after_days)}` : 'no compaction',
    p.archive ? 'archive before deleting' : 'no archive',
  ].join(' · ');
}
function rtNextRun(sch) {
  if (sch.read_only && sch.runs_on) return `Runs on ${sch.runs_on}`;
  if (sch.read_only && sch.no_runner) return 'No server runs it right now';
  if (sch.read_only) return 'Runs on the server that runs the background jobs';
  if (!sch.automatic) return 'Not scheduled on this server';
  if (!sch.next_run) return `Every ${sch.interval}`;
  const u = until(sch.next_run);
  return `${u === 'now' ? 'Next any moment' : 'Next ' + u} · every ${sch.interval}`;
}
const RT_TRIGGER = { schedule: 'Scheduled', manual: 'Run now', disk_guard: 'Disk guard', policy_change: 'Settings change' };

// ---------- loading ----------
async function rtLoad(quiet) {
  const seq = ++rtState.seq;
  clearTimeout(rtState.poll);
  if (!rtState.ov && quiet !== true) rtSkeleton();
  $('rt-refresh').disabled = true;
  let ov;
  try {
    ov = await api('api/retention');
  } catch (e) {
    if (seq !== rtState.seq) return;
    $('rt-refresh').disabled = false;
    if (!rtState.ov) rtError(e);
    else if (quiet !== true) toastError('Couldn’t refresh data retention', e);
    rtSchedule();
    return;
  }
  if (seq !== rtState.seq) return;
  $('rt-refresh').disabled = false;
  rtState.ov = ov;
  rtRender();
  rtRunFinished(ov);
  rtSchedule();
}

// rtSchedule reloads every 2 seconds while a run is going and every 30
// otherwise, only while the page is open.
function rtSchedule() {
  clearTimeout(rtState.poll);
  if (currentPage !== 'retention') return;
  const fast = rtState.ov && (rtState.ov.schedule.running || rtState.awaitRun);
  rtState.poll = setTimeout(() => {
    if (currentPage !== 'retention') return;
    if (document.hidden) { rtSchedule(); return; }
    rtLoad(true);
  }, fast ? 2000 : 30000);
}

// rtExpectRun watches for runs we started (or queued) to finish and
// reports each. After a save, a run that did nothing stays quiet: the
// save's own toast says enough. wants lists the runs still to report, in
// order, each with { quiet, title }; trigger, when set, skips runs of
// another kind (a scheduled run going when a save was queued behind it).
const rtLastStart = () => (rtState.ov && rtState.ov.last_run ? rtState.ov.last_run.started : '');
function rtExpectRun(want, before, trigger) {
  const w = rtState.awaitRun;
  if (w) {
    // A run we wait for is going: report it, then this one.
    w.wants.push(want || {});
    w.trigger = '';
    return;
  }
  rtState.awaitRun = { before: before === undefined ? rtLastStart() : before, at: Date.now(), wants: [want || {}], trigger: trigger || '' };
}
function rtRunFinished(ov) {
  const w = rtState.awaitRun;
  if (!w || ov.schedule.running) return;
  const run = ov.last_run;
  if (!run || run.started === w.before) {
    // The run has not started yet or was refused; stop waiting after a
    // while, unless one is queued.
    if (!ov.schedule.queued && Date.now() - w.at > 20000) rtState.awaitRun = null;
    return;
  }
  w.before = run.started;
  w.at = Date.now();
  if (w.trigger && run.trigger !== w.trigger) return;
  const want = w.wants.shift() || {};
  if (!w.wants.length) rtState.awaitRun = null;
  rtReportRun(run, want);
}
function rtReportRun(run, w) {
  const n = (run.errors || []).length;
  const done = [];
  if (run.archived) done.push(`archived ${rtDays(run.archived)}`);
  if (run.deleted) done.push(`deleted ${rtDays(run.deleted)}`);
  if (run.compacted) done.push(`compacted ${rtDays(run.compacted)}`);
  if (run.deleted_records) done.push(`deleted ${run.deleted_records.toLocaleString()} closed records`);
  if (w.quiet && !done.length && !n) return;
  const title = w.title && !n ? { title: w.title } : undefined;
  let msg = done.length ? `Retention ${done.join(', ')}` : n ? 'Nothing was changed' : 'Retention ran; nothing needed doing';
  if (run.freed_bytes) msg += `, freeing ${rtBytes(run.freed_bytes)}`;
  msg += '.';
  if (!done.length && n === 1) msg += ' ' + rtFix(run.errors[0]);
  if (run.skipped) msg += ` It skipped ${plural(run.skipped, 'step')} that settings saved during the run no longer call for.`;
  if (n) {
    toast(msg, { label: 'Show errors', run: () => rtSelectTab('activity', true) },
      { tone: 'danger', title: `Retention finished with ${plural(n, 'error')}` });
  } else toast(msg, null, title || {});
}

function rtSkeleton() {
  const bar = (w) => el('span', { class: 'skeleton', style: 'width:' + w });
  const stat = () => el('div', { class: 'rt-stat' }, bar('40%'), el('span', { class: 'skeleton rt-skel-value' }), bar('70%'));
  $('rt-summary').setAttribute('aria-busy', 'true');
  $('rt-summary').replaceChildren(stat(), stat(), stat(), stat());
  $('rt-table').replaceChildren(riSkeleton(RT_COLS, 6));
  $('rt-defaults').replaceChildren();
}

function rtError(e) {
  rtState.key = '';
  $('rt-summary').removeAttribute('aria-busy');
  $('rt-summary').classList.add('rt-summary--empty');
  $('rt-summary').replaceChildren(riEmpty({ icon: 'circle-alert', tone: 'danger', title: 'Couldn’t load data retention',
    text: rtSentence(e.message), action: riRetry(() => rtLoad()) }));
  $('rt-alerts').replaceChildren();
  $('rt-main').classList.add('hidden');
  $('rt-run').disabled = true;
}

// ---------- rendering ----------
// rtRender redraws the page when something visible changed, keeping focus
// on the control that had it (rows and buttons carry data-fk).
function rtRender() {
  const ov = rtState.ov;
  const key = JSON.stringify(ov) + '|' + Math.floor(Date.now() / 60000);
  if (key === rtState.key) return;
  rtState.key = key;
  const page = $('page-retention');
  const active = document.activeElement;
  const fk = active && page.contains(active) && !active.closest('dialog') ? active.dataset.fk : null;
  $('rt-main').classList.remove('hidden');
  $('rt-summary').classList.remove('rt-summary--empty');
  rtSummary(ov);
  rtAlerts(ov);
  rtTable(ov);
  rtDefaults(ov);
  rtActivity(ov);
  // The archive tab depends on this server's role and the archive folder.
  if (rtState.arch && rtState.tab === 'archive') rtRenderArchive();
  const files = (ov.archive || {}).files || 0;
  $('rt-archive-count').textContent = files.toLocaleString();
  $('rt-archive-count').classList.toggle('hidden', !files);
  const errs = ov.last_run ? (ov.last_run.errors || []).length : 0;
  $('rt-activity-count').textContent = errs;
  $('rt-activity-count').classList.toggle('hidden', !errs);
  $('rt-activity-count').title = errs ? `The last run had ${plural(errs, 'error')}` : '';
  // A server that only shows retention has no Run now, unless the
  // policies are shared: then it asks the server that runs retention.
  $('rt-run').classList.toggle('hidden', !!ov.schedule.read_only && !ov.shared);
  $('rt-run').disabled = !!ov.schedule.running || !!ov.settings_error || !!rtState.asking;
  $('rt-run').replaceChildren(icon('play'), ov.schedule.running ? (ov.schedule.current === 'restore' ? 'Restoring…' : 'Running…') : 'Run now');
  if (fk) {
    const back = page.querySelector(`[data-fk="${CSS.escape(fk)}"]`);
    if (back) back.focus({ preventScroll: true });
  }
}

function rtStat(name, label, value, sub, opts = {}) {
  const attrs = { class: 'rt-stat' };
  if (opts.tone) attrs['data-tone'] = opts.tone;
  return el('div', attrs,
    el('div', { class: 'rt-stat__label' }, icon(name), label),
    el('div', { class: 'rt-stat__value' }, ...[].concat(value)),
    opts.bar || null,
    el('div', { class: 'rt-stat__sub', title: opts.title || '' }, ...[].concat(sub)));
}

// rtMeter is a disk bar with a tick at the guard's limit. It is neutral
// until the disk passes the limit.
function rtMeter(pct, limit, tone, label) {
  const attrs = { class: 'rt-meter', role: 'img', 'aria-label': label };
  if (tone) attrs['data-tone'] = tone;
  return el('div', attrs,
    el('span', { class: 'rt-meter__fill', style: `--w:${Math.max(1, Math.min(100, pct)).toFixed(1)}%` }),
    limit ? el('i', { class: 'rt-meter__mark', style: `--at:${limit}%`, title: `Guard limit ${limit}%` }) : null);
}

function rtDiskTone(pct, g) {
  if (pct >= 95) return 'danger';
  if (g.enabled && pct > g.max_disk_percent) return 'warning';
  return '';
}

function rtSummary(ov) {
  const box = $('rt-summary');
  box.removeAttribute('aria-busy');
  const cats = ov.categories.length;
  const stored = rtStat('database', 'Stored', ov.error ? '–' : rtBytes(ov.total_bytes),
    ov.error ? 'OpenSearch didn’t answer' : `In ${plural(cats, 'category', 'categories')}, replicas included`);

  const g = ov.guard;
  let disk;
  if (ov.disk) {
    const pct = ov.disk.percent;
    const tone = rtDiskTone(pct, g);
    disk = rtStat('hard-drive', 'OpenSearch disk', `${Math.round(pct)}%`,
      `${rtBytes(ov.disk.used_bytes)} of ${rtBytes(ov.disk.total_bytes)} used`,
      { tone, title: ov.disk.node ? `Fullest data disk: ${ov.disk.node}${ov.disk.path ? ' ' + ov.disk.path : ''}` : '',
        bar: rtMeter(pct, g.enabled ? g.max_disk_percent : 0, tone, `${Math.round(pct)}% of the disk used${g.enabled ? `, guard limit ${g.max_disk_percent}%` : ''}`) });
  } else {
    disk = rtStat('hard-drive', 'OpenSearch disk', '–', 'Couldn’t read disk use', { title: ov.disk_error || '' });
  }

  const st = g.status || {};
  const gs = {
    off: ['off', 'Off', g.source === 'config' ? 'Turned off in signalith.yaml' : 'Nothing protects the disk'],
    ok: ['ok', 'On', `Acts above ${g.max_disk_percent}% disk use`],
    over: ['warn', 'Freeing space', `Disk is above ${g.max_disk_percent}%`],
    short: ['down', 'Can’t free enough', 'Add disk space or keep less'],
    unknown: ['warn', 'On', 'Disk use unknown'],
    paused: ['down', 'Paused', 'Not checking the disk until the settings file is fixed'],
  }[st.state] || ['off', g.enabled ? 'On' : 'Off', ''];
  // After a run that couldn't get under the limit, the guard waits for
  // the next scheduled run.
  if (g.paused_until && st.state !== 'paused' && st.state !== 'off') gs[2] = `Waits for the next run, ${until(g.paused_until)}`;
  // With several servers, the guard runs where retention runs: nowhere
  // right now.
  if (ov.schedule.no_runner && g.enabled) gs.splice(0, 3, 'down', 'Not running', 'No server runs retention right now');
  else if (ov.schedule.runs_on && st.state === 'ok') gs[2] = `On ${ov.schedule.runs_on}, above ${g.max_disk_percent}% disk use`;
  const dot = el('span', { class: 'rt-dot', 'data-state': gs[0], 'aria-hidden': 'true' });
  const guard = rtStat('shield', 'Disk guard', [dot, gs[1]], gs[2], { tone: gs[0] === 'down' ? 'danger' : gs[0] === 'warn' && st.state === 'over' ? 'warning' : '' });

  const sch = ov.schedule;
  const run = ov.last_run;
  let value;
  if (sch.running) value = sch.current === 'restore' ? 'Restoring now' : 'Running now';
  else if (run) value = riCap(ago(run.finished || run.started));
  else value = 'Not yet';
  const sub = [sch.running && sch.queued ? 'Another run starts when it ends' : rtNextRun(sch)];
  const errs = run && !sch.running ? (run.errors || []).length : 0;
  if (errs) {
    sub.push(' · ', el('button', { class: 'link-btn rt-err-link', type: 'button', 'data-fk': 'sum-errors', onclick: () => rtSelectTab('activity', true) }, plural(errs, 'error')));
  }
  const runs = rtStat(sch.running ? 'refresh-cw' : 'clock', 'Last run', value, sub,
    { title: run ? `${RT_TRIGGER[run.trigger] || run.trigger}, ${fmtTime(run.finished || run.started)}` : '' });
  box.replaceChildren(stored, disk, guard, runs);
}

function rtAlerts(ov) {
  const out = [];
  const p = (...t) => el('p', {}, ...t);
  if (ov.settings_error) {
    out.push(riAlert('danger', 'Retention is paused: its settings file has a mistake.',
      p('Fix or delete the file; the page picks it up without a restart. Until then nothing is deleted or compacted, the disk guard doesn’t check the disk, and settings can’t be saved here.'),
      el('p', { class: 'mono rt-alert-detail' }, ov.settings_error)));
  }
  if (ov.error) {
    out.push(riAlert('danger', 'Couldn’t read OpenSearch.', p(rtFix(ov.error)),
      p('Check that OpenSearch is running and that this server can reach it; ', el('a', { href: '#health', 'data-page': 'health' }, 'Health'),
        ' shows its state. Sizes and days show again once it answers.')));
  }
  if (ov.disk_blocked) {
    out.push(riAlert('danger', `OpenSearch has stopped writes to ${plural(ov.disk_blocked, 'index', 'indices')}.`,
      p('Its disk passed the 95% flood stage, so new events are refused. It lifts the block by itself once space is freed; the disk guard deletes the oldest days to free it.')));
  }
  const g = ov.guard;
  const st = g.status || {};
  const waits = g.paused_until && g.pause_reason
    ? p(`It waits for the next scheduled run (${until(g.paused_until)}) before trying again: ${g.pause_reason}.`) : null;
  if (st.state === 'short') out.push(riAlert('danger', 'The disk is still above the guard’s limit.', p(rtSentence(st.message)), waits));
  else if (st.state === 'over') out.push(riAlert('warning', 'The disk is above the guard’s limit.', p(rtSentence(st.message)), waits));
  else if (waits && st.state !== 'paused' && st.state !== 'off') out.push(riAlert('warning', 'The disk guard is waiting.', waits));
  for (const n of ov.notes || []) {
    if (n !== st.message) out.push(riAlert('warning', rtSentence(n)));
  }
  const sch = ov.schedule;
  const servers = () => (can('admin') ? el('a', { href: '#servers', 'data-page': 'servers' }, 'Servers page') : 'Servers page');
  if (ov.hold) {
    // The policies were imported from one server's files while another
    // server's differed: until an admin confirms them, runs only take
    // the disk guard's steps.
    const confirm = can('admin') ? el('button', { class: 'btn btn--primary btn--sm', type: 'button', id: 'rt-hold-confirm', onclick: rtConfirmHold },
      icon('check'), 'Confirm these policies') : null;
    out.push(riAlert('warning', 'These retention policies wait to be confirmed.', p(rtSentence(ov.hold.reason)),
      p('Until they are, retention deletes, archives and compacts nothing; only the disk guard acts. Check every category below, change what is wrong, then confirm.'),
      confirm ? el('div', { class: 'row' }, confirm) : null));
  }
  if (sch.read_only && ov.shared) {
    if (sch.no_runner) {
      out.push(riAlert('danger', 'No server runs retention right now.',
        el('p', {}, 'Old days are not deleted until a server runs the background jobs again. The ', servers(), ' says why.')));
    } else {
      out.push(riAlert('info', `Retention runs on ${sch.runs_on || 'the server that runs the background jobs'}.`,
        el('p', {}, 'Every server shares these policies: a change saved here applies on every server, and that server enforces it. Restores are made on that server.')));
    }
  } else if (sch.read_only && sch.no_runner) {
    out.push(riAlert('danger', 'No server runs retention right now.',
      el('p', {}, 'Old days are not deleted until a server runs the background jobs again. The ', servers(), ' says why.')));
  } else if (sch.read_only && sch.runs_on) {
    out.push(riAlert('info', `Retention runs on ${sch.runs_on}.`,
      el('p', {}, `This server only shows it. Make changes and restores on ${sch.runs_on}, with the settings saved there. The `, servers(), ' has its address.')));
  } else if (sch.read_only) {
    out.push(riAlert('info', 'This server only shows retention.',
      p(sch.read_only_why || 'Retention runs on the server that runs the background jobs, with the settings saved there. Make changes and restores on that server.')));
  } else if (!ov.schedule.automatic) {
    out.push(riAlert('info', 'Retention doesn’t run on a schedule yet.', p('It starts once the server has finished starting up.')));
  }
  $('rt-alerts').replaceChildren(...out);
}

// ---------- policies table ----------
const RT_COLS = [['Category', 'rt-c-name'], ['Size', 'num rt-c-size'], ['Oldest day', 'rt-c-oldest hide-sm'], ['Keep for', 'rt-c-keep'],
  ['Compact', 'rt-c-compact hide-md hide-sm'], ['Archive', 'rt-c-archive hide-md hide-sm'], ['Source', 'rt-c-src'], ['', 'rt-c-act hide-sm']];

function rtSourceBadge(c) {
  switch (c.source) {
    case 'ui': return el('span', { class: 'badge', title: c.from ? c.from.note : 'Its own policy, saved on this page' }, 'Custom');
    case 'config': return el('span', { class: 'badge badge--outline', title: 'From signalith.yaml; change it there' }, icon('lock', 'icon--xs'), 'signalith.yaml');
    case 'feeds': return el('span', { class: 'badge badge--outline', title: 'Each feed’s max_age decides when its indicators expire' }, 'Feeds');
    default: return el('span', { class: 'badge badge--outline', title: c.kind === 'records' ? 'Kept forever until you set a policy' : 'Uses the default policy' }, 'Default');
  }
}

// rtCanEdit: the page can change this category's policy.
const rtCanEdit = (c) => c.editable && !rtState.ov.settings_error;
// rtLock is the badge for settings the page can't change, saying why.
function rtLock(ov, source) {
  if (ov.settings_error) return el('span', { class: 'badge badge--outline', title: 'Fix the settings file first' }, icon('lock', 'icon--xs'), 'Settings file error');
  if (ov.schedule.read_only && !ov.shared) return el('span', { class: 'badge badge--outline', title: 'Change it on the server that runs the background jobs' }, icon('lock', 'icon--xs'), 'Read-only here');
  return el('span', { class: 'badge badge--outline', title: source === 'config' ? 'From signalith.yaml; change it there' : '' }, icon('lock', 'icon--xs'), 'signalith.yaml');
}

function rtRow(c, ov) {
  const records = c.kind === 'records';
  const managed = c.kind === 'managed';
  const pol = c.policy;
  const sub = (...kids) => el('span', { class: 'rt-sub' }, ...kids);
  const line = (...kids) => el('span', { class: 'rt-line' }, ...kids);

  const name = el('td', { class: 'rt-c-name' }, el('div', { class: 'rt-cat' },
    el('span', { class: 'rt-cat__icon' }, icon(RT_ICON[c.id] || 'database')),
    el('div', { class: 'rt-cat__text' }, el('div', { class: 'cell-title' }, c.name), el('span', { class: 'rt-sub', title: c.description }, c.description))));
  const size = el('td', { class: 'num rt-c-size' }, line(ov.error ? '–' : rtBytes(c.bytes)),
    sub(pol.max_size_gb ? `Cap ${rtGB(pol.max_size_gb)}` : ov.error ? '' : rtNoun(c.id, c.docs)));

  let oldest;
  if (!c.oldest_day) oldest = el('td', { class: 'rt-c-oldest hide-sm' }, rtDash());
  else {
    const bits = [];
    if (c.kind === 'monthly') bits.push(c.days === 1 ? '1 month' : `${c.days.toLocaleString()} months`);
    else if (c.kind === 'events') {
      bits.push(rtDays(c.days));
      if (c.compacted_days) bits.push(`${c.compacted_days.toLocaleString()} compacted`);
      if (c.restored_days) bits.push(`${c.restored_days.toLocaleString()} restored`);
    } else bits.push(c.id === 'findings' ? 'Oldest finding' : 'Oldest investigation');
    oldest = el('td', { class: 'rt-c-oldest hide-sm' }, line(rtDay(c.oldest_day)), sub(bits.join(' · ')));
  }

  // Keep: the main setting; under it what is due at the next run, and on
  // narrower screens the compaction and archive settings too.
  let keep;
  const due = [];
  const pd = c.pending || {};
  if (pd.delete_days) due.push(`${rtDays(pd.delete_days)} due`);
  if (pd.delete_records) due.push(`${pd.delete_records.toLocaleString()} due`);
  if (pd.compact_days) due.push(`${pd.compact_days.toLocaleString()} to compact`);
  if (managed) keep = [line(el('span', { class: 'rt-desk' }, 'Per feed'), el('span', { class: 'rt-phone' }, 'Kept per feed')), sub('Each feed’s max_age')];
  else {
    const n = pol.keep_days;
    const phone = records ? (n ? `Delete closed after ${rtDays(n)}` : 'Kept forever') : (n ? `Keep ${rtDays(n)}` : 'Kept forever');
    // Wide screens have Compact and Archive columns; narrower ones say
    // them under Keep, and phones also say "closed" in the line itself.
    const closing = records && n ? ['After closing'] : [];
    const md = [];
    if (!records) {
      if (pol.compact_after_days) md.push(`Compact after ${rtDays(pol.compact_after_days)}`);
      if (pol.archive) md.push('Archive');
    }
    const variant = (cls, parts) => (parts.length ? el('span', { class: 'rt-sub ' + cls }, parts.join(' · ')) : null);
    keep = [line(el('span', { class: 'rt-desk' }, n ? rtDays(n) : 'Forever'), el('span', { class: 'rt-phone' }, phone)),
      variant('rt-show-wide', [...closing, ...due]), variant('rt-show-md', [...closing, ...md, ...due]), variant('rt-show-phone', [...md, ...due])];
  }
  const compact = el('td', { class: 'rt-c-compact hide-md hide-sm' }, c.kind === 'events' && pol.compact_after_days ? `After ${rtDays(pol.compact_after_days)}` : rtDash());
  const archive = el('td', { class: 'rt-c-archive hide-md hide-sm' }, (c.kind === 'events' || c.kind === 'monthly') && pol.archive ? el('span', { class: 'rt-yes' }, icon('check', 'icon--sm'), 'Yes') : rtDash());

  const can = rtCanEdit(c);
  const open = () => rtOpenCategory(c.id);
  let act = null;
  if (can) {
    act = riIconBtn('pencil', `Edit the ${c.name} policy`, (ev) => { ev.stopPropagation(); open(); });
    act.tabIndex = -1;
  }
  const tr = el('tr', { 'data-id': c.id }, name, size, oldest, el('td', { class: 'rt-c-keep' }, ...keep), compact, archive,
    el('td', { class: 'rt-c-src' }, rtSourceBadge(c)), el('td', { class: 'rt-c-act hide-sm' }, act));
  if (can) {
    tr.classList.add('rt-row--edit');
    tr.dataset.fk = 'row-' + c.id;
    tr.addEventListener('click', open);
    riRowKeys(tr, open, () => false);
  }
  return tr;
}

function rtTable(ov) {
  const rows = ov.categories.map((c) => rtRow(c, ov));
  $('rt-table').replaceChildren(el('table', { class: 'table rt-table' }, riHead(RT_COLS), el('tbody', {}, ...rows)));
  const foot = $('rt-foot');
  const un = ov.unmanaged || [];
  if (un.length) {
    const names = un.map((u) => u.index);
    foot.replaceChildren(icon('info', 'icon--sm'),
      el('span', { title: names.join('\n') }, ...(un.length === 1
        ? ['Retention leaves ', el('span', { class: 'mono' }, names[0]), ' alone: it isn’t a daily index of a category.']
        : [`Retention leaves ${un.length} other indices under the prefix alone: they aren’t daily indices of a category.`])));
    foot.classList.remove('hidden');
  } else foot.classList.add('hidden');
}

// ---------- defaults card ----------
function rtDefaults(ov) {
  const d = ov.default;
  const g = ov.guard;
  const locked = !!ov.settings_error;
  const users = ov.categories.filter((c) => c.kind === 'events' && c.source === 'default').map((c) => c.name);
  const editable = !locked && (!ov.schedule.read_only || ov.shared);
  // Shared policies say where a value came from instead: a server's
  // signalith.yaml, applied when it changed, or the founder's files.
  const dsrc = d.from ? `${d.from.note}.` : ov.shared && d.source === 'days'
    ? (editable ? 'Set by retention.days, shared by every server, until you save one here.' : 'Set by retention.days, shared by every server.')
    : { days: editable ? 'Set by retention.days in signalith.yaml until you save one here.' : 'Set by retention.days in signalith.yaml.', ui: 'Saved on this page.', config: 'From signalith.yaml; change it there.' }[d.source] || '';
  const editBtn = (label, run, fk) => el('button', { class: 'btn btn--secondary btn--sm', type: 'button', 'data-fk': fk, 'aria-label': label, onclick: run }, icon('pencil'), 'Edit');
  const block = (iconName, title, value, lines, btn) => el('section', { class: 'rt-def', 'aria-label': title },
    el('div', { class: 'rt-def__head' }, el('span', { class: 'rt-cat__icon' }, icon(iconName)), el('h4', { class: 'rt-def__title' }, title), el('span', { class: 'spacer' }), btn),
    el('div', { class: 'rt-def__value' }, value),
    ...lines.filter(Boolean).map((t) => el('p', { class: 'rt-def__line' }, t)));

  const p = d.policy;
  const rest = rtPolicyText(p).split(' · ').slice(1).join(' · ');
  const def = block('layers', 'Default policy', p.keep_days ? `Keep ${rtDays(p.keep_days)}` : 'Keep forever',
    [riCap(rest) + '.', users.length ? `Used by ${users.join(', ')}.` : 'No category uses it now.', dsrc],
    d.editable && !locked ? editBtn('Edit the default policy', rtOpenDefault, 'def-edit') : rtLock(ov, d.source));

  const gsrc = g.from ? `${g.from.note}.` : { builtin: 'Built-in settings.', ui: 'Saved on this page.', config: 'From signalith.yaml; change it there.' }[g.source] || '';
  const guard = block('shield', 'Disk guard', g.enabled ? `On above ${g.max_disk_percent}% disk use` : 'Off',
    [g.enabled ? `Deletes the oldest event days first, never the last ${rtDays(g.min_days)}, and only when that gets the disk under the limit.` : 'OpenSearch stops taking new events when its disk reaches 95%.',
      locked && g.enabled ? 'Paused: it doesn’t check the disk until the settings file is fixed.' : gsrc],
    g.editable && !locked ? editBtn('Edit the disk guard', rtOpenGuard, 'guard-edit') : rtLock(ov, g.source));

  $('rt-defaults').replaceChildren(el('div', { class: 'card__head' }, el('div', {}, el('h3', { class: 'card__title' }, 'Defaults'),
    el('p', { class: 'card__sub' }, 'For event categories without their own policy, and for the disk as a whole.'))),
  el('div', { class: 'rt-defs' }, def, guard));
}

// ---------- activity ----------
const RT_ACTION = {
  compact: ['layers', 'Compacted'], archive: ['archive', 'Archived'], delete: ['trash-2', 'Deleted'],
  delete_records: ['trash-2', 'Deleted'], restore: ['rotate-ccw', 'Restored'],
};
const RT_FAILED = { compact: 'Compaction failed', archive: 'Archive failed', delete: 'Delete failed', delete_records: 'Delete failed', restore: 'Restore failed' };

// rtGroupActions folds the actions of one run that share a kind, category
// and reason into one row: "Compacted 60 days". Actions closer than ten
// minutes apart count as one run. Failures stay on their own rows.
function rtGroupActions(acts) {
  const out = [];
  let burst = new Map();
  let prev = null;
  for (const a of acts) {
    const t = new Date(a.time).getTime();
    if (prev === null || Math.abs(prev - t) > 10 * 60 * 1000) burst = new Map();
    prev = t;
    const key = !a.error && a.day ? [a.action, a.category, a.reason, a.by, a.server].join('\u0000') : null;
    const g = key && burst.get(key);
    if (g) {
      g.days.push(a.day);
      g.indices.push(a.index);
      g.bytes += a.bytes || 0;
      g.freed += a.freed || 0;
      g.docs += a.docs || 0;
      continue;
    }
    const row = { ...a, days: a.day ? [a.day] : [], indices: a.index ? [a.index] : [], bytes: a.bytes || 0, freed: a.freed || 0, docs: a.docs || 0 };
    if (key) burst.set(key, row);
    out.push(row);
  }
  return out;
}

function rtActivity(ov) {
  const run = ov.last_run;
  const sch = ov.schedule;
  const box = $('rt-lastrun');
  const head = (sub) => el('div', { class: 'card__head' }, el('div', {}, el('h3', { class: 'card__title' }, 'Last run'), sub ? el('p', { class: 'card__sub' }, sub) : null));
  if (!run) {
    box.replaceChildren(head(rtNextRun(sch)), riEmpty({ icon: 'clock', title: sch.running ? 'Running now' : 'No runs yet',
      text: sch.read_only ? 'Retention runs on the server that runs the background jobs, not on this one.'
        : 'The first scheduled run starts 2 minutes after the server starts. Run now runs it sooner.' }));
  } else {
    const secs = Math.max(0, Math.round((new Date(run.finished) - new Date(run.started)) / 1000));
    const took = secs < 1 ? 'under a second' : secs < 60 ? `${secs}s` : `${Math.round(secs / 60)}m`;
    const who = run.by ? ` by ${run.by}` : '';
    const subText = `${riCap(ago(run.finished))} · ${RT_TRIGGER[run.trigger] || run.trigger}${who} · took ${took}`;
    const stats = [];
    const stat = (n, label) => { if (n) stats.push(el('div', { class: 'rt-run-stat' }, el('b', { class: 'num' }, n.toLocaleString()), label)); };
    stat(run.archived, run.archived === 1 ? 'day archived' : 'days archived');
    stat(run.deleted, run.deleted === 1 ? 'day deleted' : 'days deleted');
    stat(run.compacted, run.compacted === 1 ? 'day compacted' : 'days compacted');
    stat(run.deleted_records, run.deleted_records === 1 ? 'closed record deleted' : 'closed records deleted');
    stat(run.skipped, run.skipped === 1 ? 'step skipped: settings changed' : 'steps skipped: settings changed');

    if (run.freed_bytes) stats.push(el('div', { class: 'rt-run-stat' }, el('b', { class: 'num' }, rtBytes(run.freed_bytes)), 'freed'));
    const errs = run.errors || [];
    const body = el('div', { class: 'card__body rt-run' },
      stats.length ? el('div', { class: 'rt-run-stats' }, ...stats) : el('p', { class: 'muted' }, 'Nothing needed doing: every category was within its policy.'),
      errs.length ? riAlert('danger', `${plural(errs.length, 'thing')} failed and ${errs.length === 1 ? 'was' : 'were'} left as ${errs.length === 1 ? 'it was' : 'they were'}. The next run tries again.`,
        el('ul', { class: 'rt-errs' }, ...errs.slice(0, 10).map((e) => el('li', {}, rtFix(e)))),
        errs.length > 10 ? el('p', {}, `and ${errs.length - 10} more in the server log`) : null) : null);
    box.replaceChildren(head(subText), body);
  }

  const acts = ov.recent || [];
  const catName = {};
  for (const c of ov.categories) catName[c.id] = c.name;
  if (!acts.length) {
    $('rt-actions').replaceChildren(riEmpty({ icon: 'history', title: 'Nothing yet', text: 'Each day retention compacts, archives, deletes or restores shows here, with the reason.' }));
    return;
  }
  const rows = rtGroupActions(acts).map((a) => {
    const failed = !!a.error;
    const n = a.days.length;
    const [ic, label] = RT_ACTION[a.action] || ['circle-dot', riCap(a.action)];
    const cat = catName[a.category] || a.category;
    const what = n ? `${cat} · ${rtRange(a.days)}` : cat;
    let amount = '';
    if (failed) amount = a.bytes ? rtBytes(a.bytes) : '';
    else if (a.action === 'restore') amount = rtNoun('', a.docs);
    else if (a.action === 'delete_records') amount = rtNoun(a.category, a.docs);
    else if (a.freed) amount = `${rtBytes(a.freed)} freed`;
    else if (a.bytes) amount = rtBytes(a.bytes);
    const why = failed
      ? el('span', { class: 'rt-bad' }, rtFix(a.error))
      : [a.reason ? rtSentence(a.reason) : '', a.by ? el('span', { class: 'subtle' }, ` By ${a.by}.`) : null,
        a.server ? el('span', { class: 'subtle' }, ` On ${a.server}.`) : null];
    const ix = [...a.indices].sort();
    const title = ix.length > 1 ? `${ix[0]} to ${ix[ix.length - 1]}` : ix[0] || '';
    return el('tr', failed ? { 'data-failed': '' } : {},
      el('td', { class: 'rt-a-when' }, el('span', { class: 'age', title: fmtTime(a.time) }, ago(a.time))),
      el('td', { class: 'rt-a-what' }, el('span', failed ? { class: 'rt-act', 'data-failed': '' } : { class: 'rt-act' }, icon(failed ? 'circle-alert' : ic, 'icon--sm'),
        failed ? RT_FAILED[a.action] || 'Failed' : n > 1 ? `${label} ${rtDays(n)}` : label),
      el('span', { class: 'rt-sub', title }, what)),
      el('td', { class: 'num rt-a-size' }, amount),
      el('td', { class: 'rt-a-why' }, ...[].concat(why)));
  });
  $('rt-actions').replaceChildren(el('table', { class: 'table rt-acts' },
    riHead([['When', 'rt-a-when'], ['What', 'rt-a-what'], ['Size', 'num rt-a-size'], ['Why', 'rt-a-why']]), el('tbody', {}, ...rows)));
}

// ---------- tabs ----------
const RT_TABS = ['policies', 'archive', 'activity'];
function rtSelectTab(name, focus) {
  if (!RT_TABS.includes(name)) name = 'policies';
  rtState.tab = name;
  for (const t of RT_TABS) {
    const tab = $('rt-tab-' + t);
    tab.setAttribute('aria-selected', String(t === name));
    tab.tabIndex = t === name ? 0 : -1;
    $('rt-panel-' + t).hidden = t !== name;
  }
  if (focus) $('rt-tab-' + name).focus();
  try { localStorage.setItem('signalith.retention.tab', name); } catch (_) { /* storage may be blocked */ }
  if (name === 'archive') rtLoadArchive();
  else clearTimeout(rtState.archPoll);
}
for (const t of RT_TABS) {
  const tab = $('rt-tab-' + t);
  tab.addEventListener('click', () => rtSelectTab(t));
  tab.addEventListener('keydown', (ev) => {
    const i = RT_TABS.indexOf(t);
    let next = null;
    if (ev.key === 'ArrowRight') next = RT_TABS[(i + 1) % RT_TABS.length];
    else if (ev.key === 'ArrowLeft') next = RT_TABS[(i + RT_TABS.length - 1) % RT_TABS.length];
    else if (ev.key === 'Home') next = RT_TABS[0];
    else if (ev.key === 'End') next = RT_TABS[RT_TABS.length - 1];
    if (!next) return;
    ev.preventDefault();
    rtSelectTab(next, true);
  });
}
try { rtState.tab = localStorage.getItem('signalith.retention.tab') || 'policies'; } catch (_) { /* ignore */ }

// ---------- field errors ----------
function rtClearErrors(form) {
  form.querySelectorAll('.rt-set .field-error').forEach((n) => n.remove());
  form.querySelectorAll('[aria-invalid]').forEach((n) => {
    n.removeAttribute('aria-invalid');
    const d = (n.getAttribute('aria-describedby') || '').split(' ').filter((x) => x && !x.endsWith('-err')).join(' ');
    if (d) n.setAttribute('aria-describedby', d); else n.removeAttribute('aria-describedby');
  });
}
function rtSetError(input, text) {
  const row = input.closest('.rt-set');
  input.setAttribute('aria-invalid', 'true');
  const id = input.id + '-err';
  input.setAttribute('aria-describedby', [(input.getAttribute('aria-describedby') || ''), id].join(' ').trim());
  row.append(el('p', { class: 'field-error', id }, icon('circle-alert'), text));
}
// rtNum reads a number input: '' is null, anything that is not a whole
// (or, with decimals, any) number is NaN.
function rtNum(input, decimals) {
  const v = input.value.trim();
  if (v === '') return null;
  const n = Number(v);
  if (!isFinite(n) || (!decimals && !Number.isInteger(n))) return NaN;
  return n;
}

// ---------- preview ----------
// rtPreview fetches what a change would do; the same body is asked once.
const rtPrev = { key: '', promise: null };
function rtPreviewFetch(body) {
  const key = JSON.stringify(body);
  if (rtPrev.key !== key || !rtPrev.promise) {
    rtPrev.key = key;
    rtPrev.promise = api('api/retention/preview', body).then((r) => ({ ok: true, r }), (e) => ({ ok: false, e }));
  }
  return rtPrev.promise;
}

function rtPreviewLine(tone, name, title, sub) {
  const attrs = { class: 'rt-pv' };
  if (tone) attrs['data-tone'] = tone;
  return el('div', attrs, icon(name), el('div', {}, el('b', {}, title), sub ? el('p', {}, sub) : null));
}

// rtPreviewView describes a preview reply in a sentence or two, with the
// days it touches under a disclosure. The run that saving starts also does
// whatever is already due, so that is said too.
function rtPreviewView(p, guard) {
  const s = p.summary;
  const out = [];
  const removes = p.steps.filter((d) => d.action === 'archive' || d.action === 'delete');
  const compacts = p.steps.filter((d) => d.action === 'compact');
  const dueSteps = p.due_steps || [];
  const dueRemoves = dueSteps.filter((d) => d.action === 'archive' || d.action === 'delete');
  const dueCompacts = dueSteps.filter((d) => d.action === 'compact');
  const dueRecords = p.due_records || [];
  if (removes.length) {
    const cats = new Set(removes.map((d) => d.category));
    const across = cats.size > 1 ? ` across ${cats.size} categories` : '';
    let t;
    if (s.archive_days === s.delete_days) t = `Saving archives ${rtDays(s.delete_days)}${across}, then deletes them from OpenSearch (${rtBytes(s.delete_bytes)}).`;
    else if (s.archive_days) t = `Saving deletes ${rtDays(s.delete_days)}${across} (${rtBytes(s.delete_bytes)}) now; ${s.archive_days.toLocaleString()} of them are archived first.`;
    else t = `Saving deletes ${rtDays(s.delete_days)}${across} (${rtBytes(s.delete_bytes)}) now.`;
    const guardSteps = removes.filter((d) => d.rule === 'guard').length;
    let sub = rtRange(removes.map((d) => d.day));
    if (guardSteps) sub += ` · ${guardSteps.toLocaleString()} by the disk guard`;
    out.push(rtPreviewLine('warning', s.archive_days === s.delete_days ? 'archive' : 'trash-2', t, sub));
  }
  if (compacts.length) {
    out.push(rtPreviewLine('', 'layers', `Saving compacts ${rtDays(s.compact_days)} (${rtBytes(s.compact_bytes)}).`,
      `${rtRange(compacts.map((d) => d.day))} · read-only and merged, so they take less space. Events that arrive later for these days are refused and lost.`));
  }
  for (const r of p.records || []) {
    const what = r.category === 'findings' ? (r.count === 1 ? 'finding' : 'findings') : (r.count === 1 ? 'investigation' : 'investigations');
    out.push(rtPreviewLine('warning', 'trash-2', `Saving deletes ${r.count.toLocaleString()} resolved or closed ${what}.`,
      `Unchanged since before ${rtDay(String(r.before).slice(0, 10), true)}`));
  }
  // What is due under the current settings anyway: the run that saving
  // starts does it now.
  const due = p.due || {};
  const dueBits = [];
  if (due.delete_days) dueBits.push(`${due.archive_days === due.delete_days ? 'archives and deletes' : 'deletes'} ${rtDays(due.delete_days)} (${rtBytes(due.delete_bytes)})`);
  if (due.compact_days) dueBits.push(`compacts ${rtDays(due.compact_days)}`);
  const dueRecs = dueRecords.reduce((n, r) => n + r.count, 0);
  if (dueRecs) dueBits.push(`deletes ${plural(dueRecs, 'closed record')}`);
  if (dueBits.length) {
    const days = [...dueRemoves, ...dueCompacts].map((d) => d.day);
    out.push(rtPreviewLine(due.delete_days || dueRecs ? 'warning' : '', due.delete_days || dueRecs ? 'trash-2' : 'layers',
      `${out.length ? 'Saving also' : 'Saving'} ${rtJoin(dueBits)} that ${due.delete_days + due.compact_days + dueRecs === 1 ? 'is' : 'are'} already due.`,
      `${days.length ? rtRange(days) + ' · ' : ''}Due under the current settings; the run that saving starts does it now.`));
  }
  if (!out.length) {
    const gs = p.guard || {};
    let why = 'The policy applies as days get older.';
    if (guard) why = !guard.enabled ? 'Policies still delete days as they get older.' : gs.message ? rtSentence(gs.message) : '';
    out.push(rtPreviewLine('', 'circle-check', guard ? 'Saving deletes nothing now.' : 'Saving deletes and compacts nothing now.', why));
  }
  if (p.guard && p.guard.state === 'short') out.push(rtPreviewLine('danger', 'triangle-alert', 'The disk would stay above the guard’s limit.', rtSentence(p.guard.message)));
  for (const n of p.notes || []) if (!p.guard || n !== p.guard.message) out.push(rtPreviewLine('warning', 'triangle-alert', rtSentence(n)));
  const touched = [...removes, ...compacts, ...dueRemoves, ...dueCompacts];
  if (touched.length) {
    const max = 60;
    const multi = new Set(touched.map((d) => d.category)).size > 1;
    const names = {};
    for (const c of (rtState.ov || { categories: [] }).categories) names[c.id] = c.name;
    const verb = { archive: 'Archive', delete: 'Delete', compact: 'Compact' };
    const dueSet = new Set(dueSteps);
    out.push(el('details', { class: 'rt-steps' },
      el('summary', {}, icon('chevron-down', 'icon--sm chev'), `Show the ${touched.length === 1 ? 'day' : touched.length.toLocaleString() + ' days'}`),
      el('ul', { class: 'rt-steps__list' }, ...touched.slice(0, max).map((d) => el('li', {},
        el('span', { class: 'rt-steps__day' }, rtDay(d.day, true)),
        el('span', { class: 'rt-steps__what' }, verb[d.action] || d.action,
          multi ? el('span', { class: 'subtle' }, ' · ' + (names[d.category] || d.category)) : null,
          dueSet.has(d) ? el('span', { class: 'subtle' }, ' · already due') : null),
        el('span', { class: 'rt-steps__size num' }, rtBytes(d.bytes)))),
      touched.length > max ? el('li', { class: 'subtle' }, `and ${(touched.length - max).toLocaleString()} more`) : null)));
  }
  return out;
}
// rtJoin joins phrases: "a", "a and b", "a, b and c".
const rtJoin = (xs) => (xs.length < 2 ? xs.join('') : `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}`);

// rtShowPreview runs a preview for a form and draws it in box. It returns
// the reply, or null when the change is not valid.
async function rtShowPreview(box, body, onFields) {
  const key = JSON.stringify(body);
  box.dataset.key = key;
  box.setAttribute('aria-busy', 'true');
  if (!box.firstChild || box.dataset.state !== 'ok') box.replaceChildren(rtPreviewLine('', 'refresh-cw', 'Checking what saving does…'));
  box.dataset.state = 'loading';
  const res = await rtPreviewFetch(body);
  if (box.dataset.key !== key) return null;
  box.removeAttribute('aria-busy');
  if (!res.ok) {
    box.dataset.state = 'error';
    const fields = rtProblemFields(res.e.problems);
    if (fields.length && onFields) {
      onFields(res.e.problems);
      box.replaceChildren(rtPreviewLine('', 'info', 'Fix the setting marked above to see what saving does.'));
    } else if (rtUnchecked(res)) {
      box.replaceChildren(rtPreviewLine('warning', 'triangle-alert', 'OpenSearch isn’t answering, so what saving deletes can’t be checked.',
        'You can still save: the change applies at the first run once OpenSearch answers. Check that OpenSearch is running; Health shows its state.'));
    } else box.replaceChildren(rtPreviewLine('danger', 'circle-alert', 'Couldn’t check what saving does.', `${rtFix(res.e.message)} Try again in a moment.`));
    return res;
  }
  box.dataset.state = 'ok';
  box.replaceChildren(...rtPreviewView(res.r, body.guard));
  return res;
}
function rtProblemFields(problems) {
  return (problems || []).map((p) => String(p).split(' ')[0]).filter((f) => RT_FIELD_NAME[f]);
}
// rtUnchecked: the preview failed only because OpenSearch is down; the
// change can still be saved.
const rtUnchecked = (res) => !!res && !res.ok && res.e.status === 503;

// ---------- confirm ----------
// rtConfirm asks before a save that deletes data, describing the preview:
// what the change deletes and what is already due, since the run that
// saving starts does both. Without a preview (OpenSearch down) it says
// that what saving deletes can't be checked.
function rtConfirm(p, what, save) {
  const lines = [];
  let title;
  let button = 'Delete and save';
  if (!p) {
    title = 'Save without checking?';
    button = 'Save anyway';
    lines.push('OpenSearch isn’t answering, so what this change deletes can’t be checked now.',
      'It applies at the first run once OpenSearch answers, and deletes whatever the new settings call for then.');
  } else {
    const s = p.summary;
    const d = p.due || {};
    const removes = p.steps.filter((x) => x.action === 'archive' || x.action === 'delete');
    const dueRemoves = (p.due_steps || []).filter((x) => x.action === 'archive' || x.action === 'delete');
    const all = [...removes, ...dueRemoves];
    const days = (s.delete_days || 0) + (d.delete_days || 0);
    const archived = (s.archive_days || 0) + (d.archive_days || 0);
    const bytes = (s.delete_bytes || 0) + (d.delete_bytes || 0);
    if (days) {
      const cats = new Set(all.map((x) => x.category));
      const of = cats.size === 1 && what ? ` of ${what}` : '';
      const dueNote = d.delete_days ? ` ${d.delete_days === days ? 'All' : rtCount(d.delete_days)} of them ${d.delete_days === 1 ? 'is' : 'are'} already due under the current settings.` : '';
      if (archived === days) {
        title = `Archive and delete ${rtDays(days)}${of}?`;
        button = 'Archive, delete and save';
        lines.push(`Saving archives ${rtDays(days)} (${rtRange(all.map((x) => x.day))}), then deletes them from OpenSearch, freeing ${rtBytes(bytes)}.${dueNote}`,
          'They stop showing in searches. You can restore them from the Archive tab.');
      } else {
        title = `Delete ${rtDays(days)}${of}?`;
        lines.push(`Saving deletes ${rtDays(days)} (${rtRange(all.map((x) => x.day))}) from OpenSearch now, freeing ${rtBytes(bytes)}.${dueNote}`,
          archived ? `${archived.toLocaleString()} of them are archived first; the others can’t be brought back.` : 'They can’t be searched or brought back afterwards.');
      }
    }
    const recs = {};
    for (const r of [...(p.records || []), ...(p.due_records || [])]) recs[r.category] = (recs[r.category] || 0) + r.count;
    for (const [cat, count] of Object.entries(recs)) {
      const n = count.toLocaleString();
      const noun = cat === 'findings' ? (count === 1 ? 'finding' : 'findings') : (count === 1 ? 'investigation' : 'investigations');
      if (!title) title = `Delete ${n} closed ${noun}?`;
      lines.push(`Saving deletes ${n} resolved or closed ${noun}. This can’t be undone.`);
    }
  }
  rtState.confirm = save;
  $('rt-confirm-title').textContent = title || 'Delete data now?';
  $('rt-confirm-desc').replaceChildren(...lines.map((t) => el('p', {}, t)));
  $('rt-confirm-ok').textContent = button;

  $('rt-confirm-ok').disabled = false;
  $('rt-confirm').showModal();
  $('rt-confirm').querySelector('[data-close]').focus();
}
$('rt-confirm-ok').addEventListener('click', async () => {
  const save = rtState.confirm;
  if (!save) return;
  $('rt-confirm-ok').disabled = true;
  $('rt-confirm').close();
  rtState.confirm = null;
  await save();
});
$('rt-confirm').addEventListener('close', () => { rtState.confirm = null; });

// ---------- edit a policy ----------
// rtState.edit: { target: 'category' | 'default', cat, mode: 'default' | 'own', start }
function rtOpenCategory(id) {
  const c = rtState.ov.categories.find((x) => x.id === id);
  if (!c || !rtCanEdit(c)) return;
  rtRememberOpener();
  if (!rtState.opener) rtState.opener = 'row-' + id;
  const records = c.kind === 'records';
  // Audit records have no default policy to follow: theirs is built in.
  rtState.edit = { target: 'category', cat: c, mode: c.source === 'ui' || c.kind === 'monthly' ? 'own' : 'default' };
  $('rt-edit-title').textContent = c.name;
  $('rt-edit-desc').textContent = records
    ? (c.id === 'findings' ? 'Alerts raised by detections. Only resolved and closed findings are ever deleted.' : 'Only resolved and closed investigations are ever deleted.')
    : c.description;
  rtFillForm(c.policy, records ? 'records' : c.kind === 'monthly' ? 'monthly' : 'events', c);
  rtEditOpen();
}
function rtOpenDefault() {
  const ov = rtState.ov;
  if (!ov.default.editable) return;
  rtState.opener = 'def-edit';
  rtState.edit = { target: 'default', cat: null, mode: 'own' };
  const users = ov.categories.filter((c) => c.kind === 'events' && c.source === 'default').map((c) => c.name);
  $('rt-edit-title').textContent = 'Default policy';
  $('rt-edit-desc').textContent = users.length ? `For event categories without their own policy: ${users.join(', ')}.` : 'For event categories without their own policy. None uses it now.';
  rtFillForm(ov.default.policy, 'events', null);
  rtEditOpen();
}

function rtFillForm(p, kind, c) {
  const ov = rtState.ov;
  const form = $('rt-edit-form');
  const e = rtState.edit;
  form.dataset.kind = kind;
  $('rt-keep').value = p.keep_days || '';
  $('rt-forever').checked = !p.keep_days;
  $('rt-cap').value = p.max_size_gb || '';
  $('rt-compact').value = p.compact_after_days || '';
  $('rt-archive').checked = !!p.archive;
  if (kind === 'records') {
    $('rt-keep-label').textContent = 'Delete after';
    $('rt-forever-label').textContent = 'Keep forever';
    $('rt-keep-hint').textContent = c.id === 'findings'
      ? 'Days since a resolved or closed finding last changed. Open findings stay, and so do findings in an investigation, for as long as the investigation is kept.'
      : 'Days since a resolved or closed investigation last changed. Open ones stay, with their notes and pinned events.';
  } else if (kind === 'monthly') {
    $('rt-keep-label').textContent = 'Keep for';
    $('rt-forever-label').textContent = 'Forever';
    $('rt-keep-hint').textContent = 'Kept by month: a month is deleted once its last day is older than this. The current month is always kept.';
  } else {
    $('rt-keep-label').textContent = 'Keep searchable for';
    $('rt-forever-label').textContent = 'Forever';
    $('rt-keep-hint').textContent = c && c.oldest_day
      ? `Older days are deleted. Now ${rtDays(c.days)}, since ${rtDay(c.oldest_day, true)}.`
      : 'Older days are deleted.';
  }
  $('rt-cap-hint').textContent = c ? `Oldest days go first above it; restored days don’t count.${ov.error ? '' : ` Now ${rtBytes(c.bytes)}.`}` : 'Each category’s oldest days go first above it.';
  $('rt-archive-hint').replaceChildren('Each day is saved to ', el('span', { class: 'mono' }, ov.archive.dir || 'the archive folder'), ' first, so you can restore it.',
    ov.archive.same_disk ? ' That folder looks to be on OpenSearch’s disk, so archives take space there too.' : '');
  // Only event categories can follow the default policy.
  const choose = e.target === 'category' && kind === 'events';
  $('rt-mode').classList.toggle('hidden', !choose);
  e.start = JSON.stringify(rtFormBody());
}

function rtSetMode(mode, focus) {
  const e = rtState.edit;
  e.mode = mode;
  $('rt-mode').querySelectorAll('[data-mode]').forEach((b) => {
    const on = b.dataset.mode === mode;
    b.setAttribute('aria-checked', String(on));
    b.tabIndex = on ? 0 : -1;
    if (on && focus) b.focus();
  });
  const useDefault = e.target === 'category' && e.cat.kind === 'events' && mode === 'default';
  $('rt-settings').classList.toggle('hidden', useDefault);
  const note = $('rt-mode-note');
  const days = e.target === 'default' && rtState.ov.default.source === 'days';
  note.classList.toggle('hidden', !useDefault && !days);
  if (days) {
    const kept = rtState.ov.default.policy.keep_days || 'forever';
    note.replaceChildren(icon('info'), rtState.ov.shared
      ? el('div', {}, el('b', {}, `Now retention.days (${kept}), shared by every server.`),
        el('p', {}, 'Saving here replaces it on every server. A later change of retention.days in a server’s signalith.yaml applies again.'))
      : el('div', {}, el('b', {}, `Now retention.days (${kept}) from signalith.yaml.`),
        el('p', {}, 'Saving here replaces it on this server; signalith.yaml stays as it is.')));
  }
  if (useDefault) {
    const d = rtState.ov.default;
    note.replaceChildren(icon('layers'), el('div', {}, el('b', {}, rtPolicyText(d.policy) + '.'),
      el('p', {}, d.editable ? 'Change it under Defaults; every category that uses it follows.' : 'The default policy is set in signalith.yaml.')));
  }
}
$('rt-mode').querySelectorAll('[data-mode]').forEach((b) => {
  b.addEventListener('click', () => {
    if (rtState.edit.mode === b.dataset.mode) return;
    // Starting an own policy from the default: start from its values.
    if (b.dataset.mode === 'own' && rtState.edit.cat.source !== 'ui') {
      const d = rtState.ov.default.policy;
      $('rt-keep').value = d.keep_days || '';
      $('rt-forever').checked = !d.keep_days;
      $('rt-cap').value = d.max_size_gb || '';
      $('rt-compact').value = d.compact_after_days || '';
      $('rt-archive').checked = !!d.archive;
    }
    rtSetMode(b.dataset.mode);
    rtEditChanged();
  });
  b.addEventListener('keydown', (ev) => {
    if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(ev.key)) return;
    ev.preventDefault();
    const other = $('rt-mode').querySelector(`[data-mode="${b.dataset.mode === 'own' ? 'default' : 'own'}"]`);
    other.click();
    other.focus();
  });
});

function rtEditOpen() {
  const e = rtState.edit;
  rtPrev.key = '';
  $('rt-edit-msg').replaceChildren();
  rtClearErrors($('rt-edit-form'));
  $('rt-preview').replaceChildren();
  delete $('rt-preview').dataset.state;
  rtSetMode(e.mode);
  rtSyncForever();
  $('rt-edit').showModal();
  const first = e.target === 'category' && e.cat.kind === 'events' ? $('rt-mode').querySelector('[aria-checked="true"]') : $('rt-forever').checked ? $('rt-forever') : $('rt-keep');
  first.focus();
  rtEditChanged(true);
}

function rtSyncForever() {
  const forever = $('rt-forever').checked;
  $('rt-keep').disabled = forever;
  if (forever) $('rt-keep').value = '';
  // Compaction must come before deletion; with Forever any value works.
}

// rtFormBody is what the form would save: a policy, or null for "use the
// default" (and for findings and cases kept forever).
function rtFormBody() {
  const e = rtState.edit;
  const records = e.target === 'category' && e.cat.kind === 'records';
  if (e.target === 'category' && !records && e.mode === 'default') return null;
  const forever = $('rt-forever').checked;
  const keep = forever ? 0 : rtNum($('rt-keep'));
  if (records) return forever ? null : { keep_days: keep };
  if (e.target === 'category' && e.cat.kind === 'monthly') return { keep_days: keep, archive: $('rt-archive').checked };
  return {
    keep_days: keep,
    max_size_gb: rtNum($('rt-cap'), true) || 0,
    compact_after_days: rtNum($('rt-compact')) || 0,
    archive: $('rt-archive').checked,
  };
}

// rtCheckPolicy validates the form in the page's words; true when it is fine.
function rtCheckPolicy() {
  const form = $('rt-edit-form');
  rtClearErrors(form);
  const body = rtFormBody();
  if (!body) return true;
  let ok = true;
  const bad = (input, text) => { ok = false; rtSetError(input, text); };
  const forever = $('rt-forever').checked;
  const keep = rtNum($('rt-keep'));
  if (!forever) {
    if (keep === null) bad($('rt-keep'), 'Enter a number of days, or choose ' + $('rt-forever-label').textContent.toLowerCase() + '.');
    else if (isNaN(keep) || keep < 1) bad($('rt-keep'), 'Use a whole number of days, 1 or more.');
    else if (keep > 36500) bad($('rt-keep'), 'Use at most 36,500 days (100 years).');
  }
  if (form.dataset.kind === 'events') {
    const cap = rtNum($('rt-cap'), true);
    if (cap !== null && (isNaN(cap) || cap < 0)) bad($('rt-cap'), 'Use a size in GB, or leave it empty for no cap.');
    const comp = rtNum($('rt-compact'));
    if (comp !== null && (isNaN(comp) || comp < 0)) bad($('rt-compact'), 'Use a whole number of days, or leave it empty.');
    else if (comp && !forever && keep && comp >= keep) bad($('rt-compact'), `Use fewer days than Keep (${keep}), or days are deleted before they are compacted.`);
  }
  return ok;
}

function rtEditRequest() {
  const e = rtState.edit;
  const body = rtFormBody();
  if (e.target === 'default') return { preview: { default: body }, method: 'PUT', path: 'api/retention/default', body };
  const id = e.cat.id;
  if (body === null) return { preview: { category: id, policy: null }, method: 'DELETE', path: 'api/retention/policies/' + encodeURIComponent(id) };
  return { preview: { category: id, policy: body }, method: 'PUT', path: 'api/retention/policies/' + encodeURIComponent(id), body };
}

// rtDirty: the form differs from what is saved.
const rtDirty = () => JSON.stringify(rtFormBody()) !== rtState.edit.start;

let rtEditTimer = null;
function rtEditChanged(now) {
  clearTimeout(rtEditTimer);
  const box = $('rt-preview');
  const save = $('rt-edit-save');
  $('rt-edit-msg').replaceChildren();
  if (!rtCheckPolicy()) {
    save.disabled = true;
    box.dataset.key = '';
    box.dataset.state = 'error';
    box.replaceChildren(rtPreviewLine('', 'info', 'Fix the setting marked above to see what saving does.'));
    return;
  }
  if (!rtDirty()) {
    save.disabled = true;
    box.dataset.key = '';
    box.dataset.state = '';
    box.replaceChildren(rtPreviewLine('', 'circle-check', 'No changes yet.', 'What saving would do shows here as you change the settings.'));
    return;
  }
  save.disabled = false;
  const go = () => rtShowPreview(box, rtEditRequest().preview, (problems) => rtMarkProblems(problems, $('rt-edit-form')));
  if (now === true) go(); else rtEditTimer = setTimeout(go, 300);
}
function rtMarkProblems(problems, form) {
  const inputs = { keep_days: 'rt-keep', max_size_gb: 'rt-cap', compact_after_days: 'rt-compact', max_disk_percent: 'rt-pct', min_days: 'rt-min' };
  for (const p of problems || []) {
    const f = String(p).split(' ')[0];
    const input = inputs[f] && $(inputs[f]);
    if (input && form.contains(input) && !input.hasAttribute('aria-invalid')) rtSetError(input, rtFix(p));
  }
}

['rt-keep', 'rt-cap', 'rt-compact'].forEach((id) => $(id).addEventListener('input', () => rtEditChanged()));
$('rt-archive').addEventListener('change', () => rtEditChanged());
$('rt-forever').addEventListener('change', () => {
  rtSyncForever();
  if (!$('rt-forever').checked) {
    const e = rtState.edit;
    const was = e.target === 'default' ? rtState.ov.default.policy : e.cat.policy;
    $('rt-keep').value = was.keep_days || (e.cat && e.cat.kind === 'records' ? 365 : 90);
    $('rt-keep').focus();
    $('rt-keep').select();
  }
  rtEditChanged();
});

// rtSave sends a change; it asks first when the preview deletes data, or
// when there is no preview because OpenSearch is down. said(reply) is the
// toast for the saved change. The run that a save starts (or queues behind
// the run or restore going now) reports under it when it does something.
// rtIfMatch makes a change apply only to the policies the page shows
// (412 when someone changed them meanwhile).
const rtIfMatch = () => (rtState.ov && rtState.ov.etag ? { 'If-Match': rtState.ov.etag } : undefined);

async function rtSave(req, preview, what, msgBox, dialog, said) {
  const work = !!preview && ['steps', 'records', 'due_steps', 'due_records'].some((k) => (preview[k] || []).length > 0);
  const send = async () => {
    const before = rtLastStart();
    const busy = rtState.ov && rtState.ov.schedule.current;
    try {
      const res = await api(req.path, req.method === 'DELETE' ? undefined : req.body, req.method, rtIfMatch());
      dialog.close();
      const msg = said(res);
      const want = { quiet: true, title: msg.replace(/\.$/, '') };
      if (res.request_id) {
        // Another server runs retention: it was asked to apply the
        // change, and its result shows on its own Data retention page.
        rtFollowRun(res, `${msg} Asked ${res.queued_on || 'the server that runs retention'} to apply it now.`);
      } else if (res.run_started) {
        rtExpectRun(want, before);
        toast(work ? `${msg} Retention is applying it now.` : msg);
      } else if (res.run_queued) {
        // Keep waiting for the run already going; ours comes after it.
        rtExpectRun(want, before, 'policy_change');
        toast(`${msg} ${busy === 'restore' ? 'A restore' : 'A run'} is going now; the change applies as soon as it ends.`);
      } else toast(`${msg} It applies at the next run.`);
      rtLoad(true);
    } catch (e) {
      if (!dialog.open) dialog.showModal();
      if (e.problems && e.problems.length) rtMarkProblems(e.problems, dialog.querySelector('form'));
      if (e.status === 412) {
        // Someone changed the policies since the page read them: show
        // theirs; saving again replaces them.
        msgBox.replaceChildren(riAlert('warning', 'Someone else changed the retention policies meanwhile.', el('p', {}, rtSentence(e.message)),
          el('p', {}, 'The page now shows their change. Save again to replace it with yours.')));
        rtLoad(true);
        return;
      }
      msgBox.replaceChildren(riAlert('danger', 'Couldn’t save.', el('p', {}, rtFix(e.message))));
    }
  };
  if (!preview || preview.deletes_data) rtConfirm(preview, what, send);
  else await send();
}

$('rt-edit-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  if (!rtCheckPolicy() || !rtDirty()) return;
  const e = rtState.edit;
  const req = rtEditRequest();
  const btn = $('rt-edit-save');
  btn.disabled = true;
  clearTimeout(rtEditTimer);
  // Ask again: data may have changed since the preview was drawn.
  rtPrev.key = '';
  const res = await rtShowPreview($('rt-preview'), req.preview, (problems) => rtMarkProblems(problems, $('rt-edit-form')));
  btn.disabled = false;
  if (!res) return;
  if (!res.ok && !rtUnchecked(res)) {
    if (!rtProblemFields(res.e.problems).length) {
      $('rt-edit-msg').replaceChildren(riAlert('danger', 'Nothing was saved: what saving does couldn’t be checked.', el('p', {}, `${rtFix(res.e.message)} Try again in a moment.`)));
    }
    return;
  }
  const what = e.target === 'default' ? '' : e.cat.name;
  await rtSave(req, res.ok ? res.r : null, what, $('rt-edit-msg'), $('rt-edit'), () => {
    if (req.method === 'DELETE' && e.cat.kind === 'events') return `${e.cat.name} uses the default policy again.`;
    return e.target === 'default' ? 'Default policy saved.' : `${e.cat.name} policy saved.`;
  });
});

// ---------- disk guard ----------
function rtOpenGuard() {
  const ov = rtState.ov;
  const g = ov.guard;
  if (!g.editable) return;
  rtState.opener = 'guard-edit';

  $('rt-guard-on').checked = g.enabled;
  $('rt-pct').value = g.max_disk_percent;
  $('rt-min').value = g.min_days;
  $('rt-guard-msg').replaceChildren();
  rtClearErrors($('rt-guard-form'));
  $('rt-guard-preview').replaceChildren();
  rtState.guard = { start: JSON.stringify(rtGuardBody()) };
  rtPrev.key = '';
  rtGuardDisk();
  $('rt-guard').showModal();
  $('rt-guard-on').focus();
  rtGuardChanged(true);
}
function rtGuardBody() {
  return { enabled: $('rt-guard-on').checked, max_disk_percent: rtNum($('rt-pct')), min_days: rtNum($('rt-min')) };
}
function rtGuardDisk() {
  const ov = rtState.ov;
  const box = $('rt-guard-disk');
  const on = $('rt-guard-on').checked;
  const limit = rtNum($('rt-pct'));
  $('rt-f-pct').classList.toggle('rt-set--off', !on);
  $('rt-f-min').classList.toggle('rt-set--off', !on);
  $('rt-pct').disabled = !on;
  $('rt-min').disabled = !on;
  if (!ov.disk) {
    box.replaceChildren(el('p', { class: 'hint' }, icon('info'), 'Disk use couldn’t be read from OpenSearch.'));
    return;
  }
  const pct = ov.disk.percent;
  const lim = on && limit >= 50 && limit <= 94 ? limit : 0;
  const tone = pct >= 95 ? 'danger' : lim && pct > lim ? 'warning' : '';
  box.replaceChildren(el('div', { class: 'rt-guard-disk__row' }, el('span', {}, 'Disk now'), el('b', { class: 'num' }, `${Math.round(pct)}%`),
    el('span', { class: 'subtle' }, `${rtBytes(ov.disk.used_bytes)} of ${rtBytes(ov.disk.total_bytes)}`)),
  rtMeter(pct, lim, tone, `${Math.round(pct)}% of the disk used${lim ? `, limit ${lim}%` : ''}`));
}
function rtCheckGuard() {
  const form = $('rt-guard-form');
  rtClearErrors(form);
  if (!$('rt-guard-on').checked) return true;
  let ok = true;
  const pct = rtNum($('rt-pct'));
  const min = rtNum($('rt-min'));
  if (pct === null || isNaN(pct) || pct < 50 || pct > 94) { ok = false; rtSetError($('rt-pct'), 'Use a whole number from 50 to 94. OpenSearch stops new events at 95%.'); }
  if (min === null || isNaN(min) || min < 1 || min > 36500) { ok = false; rtSetError($('rt-min'), 'Use a whole number of days, 1 or more.'); }
  return ok;
}
let rtGuardTimer = null;
function rtGuardChanged(now) {
  clearTimeout(rtGuardTimer);
  rtGuardDisk();
  const box = $('rt-guard-preview');
  const save = $('rt-guard-save');
  $('rt-guard-msg').replaceChildren();
  if (!rtCheckGuard()) {
    save.disabled = true;
    box.dataset.key = '';
    box.replaceChildren(rtPreviewLine('', 'info', 'Fix the setting marked above to see what saving does.'));
    return;
  }
  if (JSON.stringify(rtGuardBody()) === rtState.guard.start) {
    save.disabled = true;
    box.dataset.key = '';
    box.dataset.state = '';
    box.replaceChildren(rtPreviewLine('', 'circle-check', 'No changes yet.', 'What saving would do shows here as you change the settings.'));
    return;
  }
  save.disabled = false;
  const go = () => rtShowPreview(box, { guard: rtGuardSend() }, (problems) => rtMarkProblems(problems, $('rt-guard-form')));
  if (now === true) go(); else rtGuardTimer = setTimeout(go, 300);
}
// rtGuardSend is the body to save; a guard that is off keeps its numbers.
function rtGuardSend() {
  const b = rtGuardBody();
  const g = rtState.ov.guard;
  return { enabled: b.enabled, max_disk_percent: b.enabled ? b.max_disk_percent : g.max_disk_percent, min_days: b.enabled ? b.min_days : g.min_days };
}
['rt-pct', 'rt-min'].forEach((id) => $(id).addEventListener('input', () => rtGuardChanged()));
$('rt-guard-on').addEventListener('change', () => {
  if ($('rt-guard-on').checked) {
    const g = rtState.ov.guard;
    if (rtNum($('rt-pct')) === null) $('rt-pct').value = g.max_disk_percent;
    if (rtNum($('rt-min')) === null) $('rt-min').value = g.min_days;
  }
  rtGuardChanged();
});
$('rt-guard-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  if (!rtCheckGuard() || JSON.stringify(rtGuardBody()) === rtState.guard.start) return;
  const body = rtGuardSend();
  const btn = $('rt-guard-save');
  btn.disabled = true;
  clearTimeout(rtGuardTimer);
  rtPrev.key = '';
  const res = await rtShowPreview($('rt-guard-preview'), { guard: body }, (problems) => rtMarkProblems(problems, $('rt-guard-form')));
  btn.disabled = false;
  if (!res) return;
  if (!res.ok && !rtUnchecked(res)) {
    if (!rtProblemFields(res.e.problems).length) {
      $('rt-guard-msg').replaceChildren(riAlert('danger', 'Nothing was saved: what saving does couldn’t be checked.', el('p', {}, `${rtFix(res.e.message)} Try again in a moment.`)));
    }
    return;
  }
  await rtSave({ method: 'PUT', path: 'api/retention/guard', body }, res.ok ? res.r : null, '', $('rt-guard-msg'), $('rt-guard'),
    (out) => out.enabled ? `Disk guard saved: it acts above ${out.max_disk_percent}%.` : 'Disk guard turned off.');
});

for (const d of ['rt-edit', 'rt-guard', 'rt-confirm', 'rt-restore']) {
  $(d).querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => $(d).close()));
}
// A dialog gives focus back to the control that opened it. When the page
// has redrawn meanwhile (polls redraw the table), that control is a new
// element with the same data-fk, so find it again.
function rtRememberOpener() {
  const a = document.activeElement;
  rtState.opener = a && a.dataset ? a.dataset.fk || (a.id ? '#' + a.id : '') : '';
}
for (const d of ['rt-edit', 'rt-guard', 'rt-restore']) {
  $(d).addEventListener('close', () => {
    const fk = rtState.opener;
    const page = $('page-retention');
    const a = document.activeElement;
    // Focus that the browser already gave back to a live page control stays.
    // A control inside the closed dialog does not count.
    if (!fk || $('rt-confirm').open || (a && a !== document.body && a.isConnected && page.contains(a) && !a.closest('dialog'))) return;
    const back = fk.startsWith('#') ? $(fk.slice(1)) : page.querySelector(`[data-fk="${CSS.escape(fk)}"]`);
    if (back && !back.disabled && back.offsetParent !== null) back.focus({ preventScroll: true });
  });
}

// rtFollowRun follows a request that asked the server that runs retention
// (res.queued_on) for a run: the run is made there, and its result shows
// on that server's Data retention page, as this server keeps its own run
// history. Run now stays off until the request is taken up.
function rtFollowRun(res, said) {
  const on = res.queued_on || 'the server that runs retention';
  toast(`${said} The run is made there; its result shows on ${on}’s Data retention page.`);
  rtState.asking = true;
  $('rt-run').disabled = true;
  followRequest(res.request_id).then((r) => {
    if (!r) toastError('Couldn’t follow the retention run', new Error(`The request is gone. ${on}’s Data retention page shows how it went.`));
    else if (r.state === 'failed') toastError('The retention run didn’t start', new Error(r.error || 'it failed'));
    else if (r.state === 'done') {
      const got = (r.result || {}).result;
      toast(got === 'queued' ? `${on} runs retention as soon as the run or restore going there ends.` : `${on} started the retention run.`);
    }
  }).finally(() => {
    rtState.asking = false;
    rtLoad(true);
  });
}

// ---------- run now ----------
$('rt-run').addEventListener('click', async () => {
  const btn = $('rt-run');
  btn.disabled = true;
  const before = rtLastStart();
  try {
    const res = await api('api/retention/run', {}, 'POST');
    if (res.request_id) {
      rtFollowRun(res, `Asked ${res.queued_on || 'the server that runs retention'} to run retention.`);
    } else {
      rtExpectRun({}, before);
      toast('Retention is running. The result shows here when it finishes.');
    }
  } catch (e) {
    toastError('Couldn’t start a run', e);
  }
  rtLoad(true);
});

// rtConfirmHold confirms policies that wait to be confirmed, so runs
// enforce them in full again.
async function rtConfirmHold() {
  const btn = $('rt-hold-confirm');
  if (btn) btn.disabled = true;
  try {
    const res = await api('api/retention/policies/confirm', {}, 'POST');
    toast(res.run_started || res.run_queued || res.request_id
      ? 'Policies confirmed. Retention applies them in full now.' : 'Policies confirmed. Retention applies them in full at the next run.');
  } catch (e) {
    toastError('Couldn’t confirm the policies', e);
  }
  rtLoad(true);
}

$('rt-refresh').addEventListener('click', () => {
  rtLoad();
  if (rtState.tab === 'archive') rtLoadArchive();
});

// ---------- archive ----------
// Archived days, a page at a time: a year or two of several categories is
// thousands of days. Filters narrow them by category and month. Selecting
// days, and the progress of restores, change rows in place instead of
// drawing the table again.
const RT_ARCH_COLS = [['', 'col-check'], ['Category', 'rt-ar-cat'], ['Day', 'rt-ar-day'], ['Events', 'num rt-ar-docs'], ['Size', 'num rt-ar-size hide-sm'], ['Status', 'rt-ar-state']];
const RT_ARCH_PAGE = 100;
rtState.archPage = 0;
rtState.archShown = [];

async function rtLoadArchive(quiet) {
  const seq = ++rtState.archSeq;
  clearTimeout(rtState.archPoll);
  if (!rtState.arch && quiet !== true) $('rt-arch').replaceChildren(riSkeleton(RT_ARCH_COLS, 5));
  let res;
  try {
    res = await api('api/retention/archive');
  } catch (e) {
    if (seq !== rtState.archSeq) return;
    rtState.arch = null;
    rtState.archKey = '';
    $('rt-arch-bar').classList.add('hidden');
    $('rt-arch-foot').classList.add('hidden');
    $('rt-arch-msg').replaceChildren();
    $('rt-arch').replaceChildren(riEmpty({ icon: 'circle-alert', tone: 'danger', title: 'Couldn’t read the archive', text: rtFix(e.message), action: riRetry(() => rtLoadArchive()) }));
    rtSyncRestoreButton();
    return;
  }
  if (seq !== rtState.archSeq) return;
  const wasBusy = rtArchBusy(rtState.arch);
  rtState.arch = res;
  rtRenderArchive();
  const busy = rtArchBusy(res);
  if (busy && currentPage === 'retention' && rtState.tab === 'archive') {
    rtState.archPoll = setTimeout(() => rtLoadArchive(true), 1500);
  }
  if (wasBusy && !busy) {
    rtLoad(true);
    const failed = (res.restores || []).filter((r) => r.state === 'failed' && r.finished && Date.now() - new Date(r.finished) < 60000);
    if (failed.length) toast(rtFix(failed[0].error), null, { tone: 'danger', title: `Couldn’t restore ${rtDay(failed[0].day, true)}` });
    else toast('Restore finished. The restored days show in searches now.');
  }
}
const rtArchBusy = (a) => !!a && (a.restores || []).some((r) => r.state === 'queued' || r.state === 'running');
const rtArchRowBusy = (a) => !!a.restore && (a.restore.state === 'queued' || a.restore.state === 'running');
// Only the server that runs retention restores.
// Where archives are shared, any server asks it to, and follows along.
const rtCanRestore = () => !!rtState.ov && (!rtState.ov.schedule.read_only || !!rtState.ov.restore_queued);

function rtArchState(a) {
  const r = a.restore;
  if (r && r.state === 'queued') return ['run', 'Waiting to restore', ''];
  if (r && r.state === 'running') return ['run', `Restoring ${r.docs ? Math.floor((100 * r.restored) / r.docs) : 0}%`, `${(r.restored || 0).toLocaleString()} of ${(r.docs || 0).toLocaleString()} events`];
  if (r && r.state === 'failed' && !a.searchable) return ['bad', 'Restore failed', rtFix(r.error)];
  if (a.searchable && a.restored_until) return ['ok', `Searchable until ${rtDay(a.restored_until)}`, 'Restored'];
  if (a.searchable) return ['ok', 'Also in OpenSearch', 'The day is searchable'];
  return ['', 'Archived', ''];
}
const rtArchSig = (a) => JSON.stringify(rtArchState(a));
function rtArchStateCell(td, a) {
  const [state, label, sub] = rtArchState(a);
  td.replaceChildren(el('span', { class: 'rt-state', 'data-state': state }, label), sub ? el('span', { class: 'rt-sub', title: sub }, sub) : '');
}

function rtMonthName(m) {
  const d = new Date(m + '-01T00:00:00Z');
  return isNaN(d) ? m : d.toLocaleDateString(undefined, { month: 'long', year: 'numeric', timeZone: 'UTC' });
}
// rtArchFilters fills the category and month filters from the archive,
// keeping what is chosen when it still exists.
function rtArchFilters(res) {
  const fill = (sel, opts, all) => {
    const key = JSON.stringify(opts);
    if (sel.dataset.key !== key) {
      const cur = sel.value;
      sel.dataset.key = key;
      sel.replaceChildren(el('option', { value: '' }, all), ...opts.map(([v, label]) => el('option', { value: v }, label)));
      sel.value = opts.some(([v]) => v === cur) ? cur : '';
    }
    sel.classList.toggle('hidden', opts.length < 2 && !sel.value);
  };
  const cats = [...new Map(res.archives.map((a) => [a.category, a.category_name || a.category])).entries()].sort((x, y) => x[1].localeCompare(y[1]));
  fill($('rt-arch-cat'), cats, 'All categories');
  const months = [...new Set(res.archives.map((a) => a.day.slice(0, 7)))].sort().reverse();
  fill($('rt-arch-month'), months.map((m) => [m, rtMonthName(m)]), 'All months');
}

// rtArchMatches is every archived day that matches the filters, newest
// day first.
function rtArchMatches(res) {
  const cat = $('rt-arch-cat').value;
  const month = $('rt-arch-month').value;
  return res.archives.filter((a) => (!cat || a.category === cat) && (!month || a.day.startsWith(month)))
    .sort((a, b) => (a.day !== b.day ? (a.day < b.day ? 1 : -1) : (a.category_name || a.category).localeCompare(b.category_name || b.category) || a.id.localeCompare(b.id)));
}

function rtArchRow(a, canPick) {
  const tr = el('tr', { 'data-id': a.id, 'data-sig': rtArchSig(a) });
  if (canPick) {
    const box = el('input', { type: 'checkbox', 'aria-label': `Select ${a.category_name || a.category} ${rtDay(a.day, true)}`, 'data-fk': 'arch-' + a.id });
    box.addEventListener('change', () => {
      if (box.checked) rtState.selected.add(a.id); else rtState.selected.delete(a.id);
      rtArchSyncChecks();
    });
    tr.append(el('td', { class: 'col-check' }, el('label', { class: 'check' }, box)));
    tr.addEventListener('click', (ev) => {
      if (ev.target.closest('label, input') || box.disabled) return;
      box.checked = !box.checked;
      box.dispatchEvent(new Event('change'));
    });
  }
  const state = el('td', { class: 'rt-ar-state' });
  rtArchStateCell(state, a);
  tr.append(
    el('td', { class: 'rt-ar-cat' }, el('span', { class: 'cell-title', 'data-day': ` · ${rtDay(a.day, true)}` }, a.category_name || a.category),
      el('span', { class: 'rt-sub mono', title: a.file }, a.id)),
    el('td', { class: 'rt-ar-day' }, rtDay(a.day, true)),
    el('td', { class: 'num rt-ar-docs' }, a.docs.toLocaleString()),
    el('td', { class: 'num rt-ar-size hide-sm' }, el('span', { class: 'rt-line' }, rtBytes(a.bytes)), el('span', { class: 'rt-sub', title: 'Size it had in OpenSearch' }, `was ${rtBytes(a.index_bytes)}`)),
    state);
  return tr;
}

// rtArchSyncChecks updates the check boxes, the select-all box, the
// footer and the Restore button to the selection, without redrawing.
function rtArchSyncChecks() {
  const res = rtState.arch;
  if (!res) return;
  const byId = new Map(res.archives.map((a) => [a.id, a]));
  $('rt-arch').querySelectorAll('tbody tr[data-id]').forEach((tr) => {
    const box = tr.querySelector('input[type="checkbox"]');
    const a = byId.get(tr.dataset.id);
    if (!box || !a) return;
    box.disabled = rtArchRowBusy(a);
    box.checked = rtState.selected.has(a.id);
    if (box.checked) tr.setAttribute('aria-selected', 'true'); else tr.removeAttribute('aria-selected');
  });
  const all = $('rt-arch').querySelector('thead input[type="checkbox"]');
  if (all) {
    const pickable = rtState.archShown.filter((a) => !rtArchRowBusy(a));
    const n = pickable.filter((a) => rtState.selected.has(a.id)).length;
    all.checked = pickable.length > 0 && n === pickable.length;
    all.indeterminate = n > 0 && n < pickable.length;
    all.disabled = !pickable.length;
  }
  rtArchFoot();
  rtSyncRestoreButton();
}

function rtArchFoot() {
  const res = rtState.arch;
  const shown = rtState.archShown;
  const bytes = shown.reduce((n, a) => n + a.bytes, 0);
  const docs = shown.reduce((n, a) => n + a.docs, 0);
  const sel = rtState.selected.size;
  $('rt-arch-count').textContent = `${rtDays(shown.length)} · ${rtNoun('', docs)} · ${rtBytes(bytes)}${sel ? ` · ${sel.toLocaleString()} selected` : ''}`;
  const free = rtState.ov && rtState.ov.archive.free >= 0 ? ` · ${rtBytes(rtState.ov.archive.free)} free` : '';
  $('rt-arch-dir').replaceChildren(icon('folder', 'icon--sm'), el('span', { class: 'mono' }, res.dir), free);
  const pages = Math.ceil(shown.length / RT_ARCH_PAGE);
  const start = rtState.archPage * RT_ARCH_PAGE;
  $('rt-arch-pager').classList.toggle('hidden', pages < 2);
  $('rt-arch-range').textContent = `${(start + 1).toLocaleString()}–${Math.min(start + RT_ARCH_PAGE, shown.length).toLocaleString()} of ${shown.length.toLocaleString()}`;
  $('rt-arch-prev').disabled = rtState.archPage === 0;
  $('rt-arch-next').disabled = rtState.archPage >= pages - 1;
  $('rt-arch-foot').classList.remove('hidden');
}

function rtRenderArchive() {
  const res = rtState.arch;
  const ov = rtState.ov;
  rtArchFilters(res);
  const msgs = [];
  if (res.error) msgs.push(riAlert('warning', rtFix(res.error)));
  if ((res.problems || []).length) {
    msgs.push(riAlert('warning', `${plural(res.problems.length, 'file')} in the archive folder can’t be read.`,
      el('ul', { class: 'rt-errs' }, ...res.problems.slice(0, 5).map((p) => el('li', { class: 'mono' }, p)))));
  }
  if (ov && ov.archive.same_disk && (res.archives.length || ov.categories.some((c) => c.kind === 'events' && c.policy.archive))) {
    msgs.push(riAlert('info', 'The archive folder looks to be on OpenSearch’s disk.',
      el('p', {}, 'Archiving the days the disk guard picks then takes space on the disk it is trying to free. Point retention.archive_dir at another disk.')));
  }
  if (ov && ov.archive.held_back) {
    msgs.push(riAlert('warning', 'Days that should be archived are kept for now.', el('p', {}, rtSentence(ov.archive.held_back))));
  }
  if (ov && (ov.archive.on || []).length) {
    msgs.push(riAlert('info', `Retention archiving can run on: ${ov.archive.on.join(', ')}.`,
      el('p', {}, 'These servers reach the shared archive folder. Restores asked on any server run on the one that runs retention.')));
  }
  const msgKey = JSON.stringify(msgs.map((m) => m.textContent));
  if ($('rt-arch-msg').dataset.key !== msgKey) {
    $('rt-arch-msg').dataset.key = msgKey;
    $('rt-arch-msg').replaceChildren(...msgs);
  }

  const known = new Set(res.archives.map((a) => a.id));
  for (const id of [...rtState.selected]) if (!known.has(id)) rtState.selected.delete(id);
  if (!res.archives.length) {
    rtState.archKey = '';
    rtState.archShown = [];
    $('rt-arch-bar').classList.add('hidden');
    $('rt-arch-foot').classList.add('hidden');
    $('rt-arch').replaceChildren(riEmpty({ icon: 'archive', title: 'Nothing archived yet',
      text: 'Turn on Archive before deleting in a policy, and each day is saved here before it is deleted.' }));
    rtSyncRestoreButton();
    return;
  }
  const canPick = rtCanRestore();
  $('rt-restore-open').classList.toggle('hidden', !canPick);
  // No filters to offer and nothing to restore here: no toolbar at all.
  $('rt-arch-bar').classList.toggle('hidden', !canPick && ['rt-arch-cat', 'rt-arch-month'].every((id) => $(id).classList.contains('hidden')));
  const shown = rtArchMatches(res);
  rtState.archShown = shown;
  const pages = Math.max(1, Math.ceil(shown.length / RT_ARCH_PAGE));
  rtState.archPage = Math.min(rtState.archPage, pages - 1);
  const start = rtState.archPage * RT_ARCH_PAGE;
  const rows = shown.slice(start, start + RT_ARCH_PAGE);
  if (!shown.length) {
    rtState.archKey = '';
    $('rt-arch').replaceChildren(riEmpty({ icon: 'archive', title: 'No archived days match',
      text: 'Try another category or month.', action: el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: () => {
        $('rt-arch-cat').value = '';
        $('rt-arch-month').value = '';
        rtState.archPage = 0;
        rtRenderArchive();
      } }, 'Show every day') }));
    rtArchFoot();
    rtSyncRestoreButton();
    return;
  }
  const key = JSON.stringify([canPick, rows.map((a) => a.id)]);
  const table = $('rt-arch').querySelector('table');
  if (key !== rtState.archKey || !table) {
    rtState.archKey = key;
    const head = RT_ARCH_COLS.slice(canPick ? 0 : 1).map(([h, cls]) => el('th', { class: cls }, h));
    if (canPick) {
      const all = el('input', { type: 'checkbox', 'aria-label': 'Select every day that matches the filters' });
      all.addEventListener('change', () => {
        for (const a of rtState.archShown) {
          if (rtArchRowBusy(a)) continue;
          if (all.checked) rtState.selected.add(a.id); else rtState.selected.delete(a.id);
        }
        rtArchSyncChecks();
      });
      head[0] = el('th', { class: 'col-check' }, el('label', { class: 'check' }, all));
    }
    $('rt-arch').replaceChildren(el('table', { class: 'table rt-arch-table' + (canPick ? '' : ' rt-arch--view') }, el('thead', {}, el('tr', {}, ...head)),

      el('tbody', {}, ...rows.map((a) => rtArchRow(a, canPick)))));
  } else {
    // Same rows: only redraw the status of those whose state changed.
    const byId = new Map(rows.map((a) => [a.id, a]));
    table.querySelectorAll('tbody tr[data-id]').forEach((tr) => {
      const a = byId.get(tr.dataset.id);
      const sig = a && rtArchSig(a);
      if (a && tr.dataset.sig !== sig) {
        tr.dataset.sig = sig;
        rtArchStateCell(tr.querySelector('.rt-ar-state'), a);
      }
    });
  }
  rtArchSyncChecks();
}

function rtSyncRestoreButton() {
  const n = rtState.selected.size;
  $('rt-restore-open').disabled = !n || !!(rtState.ov && rtState.ov.settings_error);
  $('rt-restore-label').textContent = n ? `Restore ${rtDays(n)}` : 'Restore';
}
for (const id of ['rt-arch-cat', 'rt-arch-month']) {
  $(id).addEventListener('change', () => { rtState.archPage = 0; rtRenderArchive(); });
}
$('rt-arch-prev').addEventListener('click', () => { rtState.archPage = Math.max(0, rtState.archPage - 1); rtRenderArchive(); });
$('rt-arch-next').addEventListener('click', () => { rtState.archPage++; rtRenderArchive(); });

// ---------- restore ----------
// The restore dialog checks first what restoring does to OpenSearch's
// disk. Restored days are spared by size caps and the disk guard, so if
// they take the disk over the guard's limit, the guard deletes other live
// days to make room. The dialog then says which, and Restore becomes
// "Restore anyway"; the server refuses such a restore without it.
$('rt-restore-open').addEventListener('click', () => {
  const res = rtState.arch;
  if (!res || !rtState.selected.size) return;
  rtState.opener = '#rt-restore-open';
  const picked = res.archives.filter((a) => rtState.selected.has(a.id));
  const n = picked.length;
  $('rt-restore-title').textContent = n === 1 ? `Restore ${picked[0].category_name || picked[0].category}, ${rtDay(picked[0].day, true)}?` : `Restore ${rtDays(n)}?`;
  const docs = picked.reduce((s, a) => s + a.docs, 0);
  const live = picked.filter((a) => a.searchable).length;
  $('rt-restore-desc').textContent = (n === 1 ? `Its ${rtNoun('', docs)} go back into the original index, so searches find them again.`
    : `Their ${rtNoun('', docs)} go back into the original indices, so searches find them again.`) +
    (live ? ` ${live === n ? (n === 1 ? 'It is' : 'They are') : `${live} of them are`} searchable now; restoring again sets a new date.` : '');
  $('rt-rkeep').value = res.default_keep_days || 14;
  $('rt-rkeep').max = res.max_keep_days || 365;
  rtRestoreHint();
  $('rt-restore-msg').replaceChildren();
  rtClearErrors($('rt-restore-form'));
  $('rt-restore').showModal();
  $('rt-rkeep').focus();
  $('rt-rkeep').select();
  rtRestoreCheck();
});

function rtRestoreOk(chk) {
  const btn = $('rt-restore-ok');
  const n = rtState.selected.size;
  const confirm = !!(chk && chk.needs_confirm);
  btn.textContent = confirm ? 'Restore anyway' : n === 1 ? 'Restore' : `Restore ${rtDays(n)}`;
  btn.classList.toggle('btn--danger', confirm);
  btn.classList.toggle('btn--primary', !confirm);
  btn.disabled = !chk;
}

async function rtRestoreCheck() {
  const seq = (rtState.restoreSeq = (rtState.restoreSeq || 0) + 1);
  const box = $('rt-restore-check');
  rtState.restoreCheck = null;
  rtRestoreOk(null);
  box.setAttribute('aria-busy', 'true');
  box.replaceChildren(rtPreviewLine('', 'refresh-cw', 'Checking how much room the days need…'));
  const keep = rtNum($('rt-rkeep'));
  let chk;
  try {
    chk = await api('api/retention/archive/preview', { ids: [...rtState.selected], keep_days: keep >= 1 && keep <= 365 ? keep : 0 });
  } catch (e) {
    if (seq !== rtState.restoreSeq) return;
    box.removeAttribute('aria-busy');
    box.replaceChildren(e.status === 503
      ? rtPreviewLine('danger', 'circle-alert', 'OpenSearch isn’t answering, so nothing can be restored now.', 'Check that OpenSearch is running; Health shows its state. Then try again.')
      : rtPreviewLine('danger', 'circle-alert', 'Couldn’t check what restoring does.', `${rtFix(e.message)} Try again in a moment.`));
    return;
  }
  if (seq !== rtState.restoreSeq) return;
  box.removeAttribute('aria-busy');
  rtState.restoreCheck = chk;
  box.replaceChildren(...rtRestoreView(chk));
  rtRestoreOk(chk);
}

function rtRestoreView(chk) {
  const out = [];
  const ov = rtState.ov;
  const limit = ov && ov.guard.enabled ? ov.guard.max_disk_percent : 0;
  const steps = chk.steps || [];
  if (chk.disk) {
    const now = Math.round(chk.disk.percent);
    const after = Math.round(chk.percent_after);
    const tone = chk.flood ? 'danger' : chk.over_limit || steps.length ? 'warning' : '';
    out.push(el('div', { class: 'rt-guard-disk' },
      el('div', { class: 'rt-guard-disk__row' }, el('span', {}, 'Disk after'), el('b', { class: 'num' }, `${after}%`),
        el('span', { class: 'subtle' }, chk.bytes ? `now ${now}%, adds about ${rtBytes(chk.bytes)}` : `now ${now}%`)),
      rtMeter(chk.percent_after, limit, tone, `About ${after}% of the disk used after restoring${limit ? `, guard limit ${limit}%` : ''}`)));
  } else if (chk.bytes) {
    out.push(rtPreviewLine('', 'info', `Adds about ${rtBytes(chk.bytes)} to OpenSearch.`, 'Disk use couldn’t be read, so how full the disk gets can’t be checked.'));
  }
  if (chk.flood) {
    out.push(rtPreviewLine('danger', 'triangle-alert', 'This could fill OpenSearch’s disk.', rtSentence(chk.message)));
  }
  if (steps.length) {
    const d = chk.deletes || {};
    out.push(rtPreviewLine('warning', 'trash-2', `To make room, the disk guard then deletes ${rtDays(d.delete_days)} of live data (${rtBytes(d.delete_bytes)}).`,
      chk.unarchived ? `${chk.unarchived === steps.length ? (steps.length === 1 ? 'It isn’t' : 'None of them is') : `${chk.unarchived.toLocaleString()} of them aren’t`} archived, so ${chk.unarchived === 1 ? 'it' : 'those'} can’t be brought back. Free disk space first, or restore fewer days.`
        : 'They are archived first, so they can be restored later.'));
    const names = {};
    for (const c of (ov || { categories: [] }).categories) names[c.id] = c.name;
    const max = 30;
    out.push(el('details', { class: 'rt-steps' },
      el('summary', {}, icon('chevron-down', 'icon--sm chev'), `Show the ${steps.length === 1 ? 'day' : steps.length.toLocaleString() + ' days'}`),
      el('ul', { class: 'rt-steps__list' }, ...rtUnarchivedFirst(steps).slice(0, max).map((s) => el('li', {},
        el('span', { class: 'rt-steps__day' }, rtDay(s.day, true)),
        el('span', { class: 'rt-steps__what' }, names[s.category] || s.category,
          el('span', { class: 'subtle' }, rtArchivedFirst(s) ? ' · archived first' : ' · not archived')),
        el('span', { class: 'rt-steps__size num' }, rtBytes(s.bytes)))),
      steps.length > max ? el('li', { class: 'subtle' }, `and ${(steps.length - max).toLocaleString()} more`) : null)));
  } else if (chk.over_limit && !chk.flood) {
    out.push(rtPreviewLine('warning', 'triangle-alert', 'The disk would go above the guard’s limit.', rtSentence(chk.message)));
  } else if (!chk.flood) {
    out.push(rtPreviewLine('', 'circle-check', chk.bytes ? 'Nothing else is deleted to make room.' : 'These days are still in OpenSearch, so restoring takes no more room.',
      chk.bytes && limit ? `The disk stays below the ${limit}% disk guard.` : ''));
  }
  return out;
}

// rtUnarchivedFirst lists the days that can't be brought back first.
const rtArchivedFirst = (s) => s.action === 'archive' || /already archived/.test(s.reason);
const rtUnarchivedFirst = (steps) => [...steps].sort((a, b) => rtArchivedFirst(a) - rtArchivedFirst(b));

function rtRestoreHint() {
  const n = rtNum($('rt-rkeep'));
  const max = (rtState.arch && rtState.arch.max_keep_days) || 365;
  if (n && n >= 1 && n <= max) {
    const until = new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);
    $('rt-rkeep-hint').textContent = `Until ${rtDay(until, true)}. Then retention deletes them again; the archive files stay.`;
  } else $('rt-rkeep-hint').textContent = `From 1 to ${max} days. Then retention deletes them again; the archive files stay.`;
}
$('rt-rkeep').addEventListener('input', () => { rtClearErrors($('rt-restore-form')); rtRestoreHint(); });
$('rt-restore-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const max = (rtState.arch && rtState.arch.max_keep_days) || 365;
  const keep = rtNum($('rt-rkeep'));
  rtClearErrors($('rt-restore-form'));
  if (keep === null || isNaN(keep) || keep < 1 || keep > max) {
    rtSetError($('rt-rkeep'), `Use a whole number of days from 1 to ${max}.`);
    $('rt-rkeep').focus();
    return;
  }
  const chk = rtState.restoreCheck;
  if (!chk) return;
  const ids = [...rtState.selected];
  const btn = $('rt-restore-ok');
  btn.disabled = true;
  try {
    const res = await api('api/retention/archive/restore', { ids, keep_days: keep, confirm: !!chk.needs_confirm }, 'POST');
    $('rt-restore').close();
    rtState.selected.clear();
    const n = res.request_id ? ids.length : (res.restores || []).length;
    toast(res.request_id
      ? `Asked ${res.queued_on || 'the server that runs retention'} to restore ${rtDays(n)}. Each is searchable as soon as it finishes.`
      : `Restoring ${rtDays(n)}. Each is searchable as soon as it finishes.`);
    rtLoadArchive(true);
    rtLoad(true);
  } catch (e) {
    if (e.status === 409 && !chk.needs_confirm) {
      // Something changed since the check: show it again before restoring.
      await rtRestoreCheck();
      if (rtState.restoreCheck && rtState.restoreCheck.needs_confirm) {
        $('rt-restore-msg').replaceChildren(riAlert('warning', 'Things changed since the check. Look again, then restore.'));
        return;
      }
    }
    btn.disabled = false;
    $('rt-restore-msg').replaceChildren(riAlert('danger', 'Couldn’t start the restore.', el('p', {}, rtFix(e.message))));
  }
});

// ---------- page ----------
pageHooks.push((name) => {
  if (name !== 'retention') {
    clearTimeout(rtState.poll);
    clearTimeout(rtState.archPoll);
    return;
  }
  rtSelectTab(rtState.tab);
  rtLoad();
});
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && currentPage === 'retention' && rtState.ov) rtLoad(true);
});
