"""
PyForensix GUI Dashboard — Tkinter-based forensic investigation interface.
Dark terminal aesthetic with tabbed panels for each scan domain.
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import platform
import os
import json
import sys
from datetime import datetime
from typing import Dict, Any, List, Optional

# Colour palette
BG         = '#0a0e1a'
BG2        = '#0f1526'
BG3        = '#151d35'
ACCENT     = '#00d4aa'
ACCENT2    = '#4fc3f7'
RED        = '#ff4757'
ORANGE     = '#ff6b35'
YELLOW     = '#ffa502'
GREEN      = '#2ed573'
BLUE       = '#70a1ff'
TEXT       = '#e0e8ff'
TEXT2      = '#7889b0'
BORDER     = '#1e2a4a'
FONT_MONO  = ('Courier New', 10)
FONT_MONO_S= ('Courier New', 9)
FONT_MONO_L= ('Courier New', 12)
FONT_UI    = ('Courier New', 10)

SEV_COLORS = {
    'CRITICAL': RED,
    'HIGH':     ORANGE,
    'MEDIUM':   YELLOW,
    'LOW':      GREEN,
    'OK':       TEXT2,
    'INFO':     BLUE,
    'CLEAN':    GREEN,
}


def _sev_tag(sev: str) -> str:
    return {
        'CRITICAL': 'sev_crit',
        'HIGH':     'sev_high',
        'MEDIUM':   'sev_med',
        'LOW':      'sev_low',
        'OK':       'sev_ok',
    }.get(sev, 'sev_ok')


class PyForensixGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title('⚡ PyForensix — Forensic Analysis Suite')
        self.root.configure(bg=BG)
        self.root.geometry('1280x820')
        self.root.minsize(1024, 700)

        self._scan_results: Dict[str, Any] = {}
        self._report = None
        self._scanning = False

        self._style()
        self._build_ui()
        self._status('Ready. Click [Run Full Scan] to begin.')

    # ── Tkinter style ──────────────────────────────────────────────────────────

    def _style(self):
        style = ttk.Style(self.root)
        style.theme_use('default')
        style.configure('TNotebook',              background=BG,  borderwidth=0)
        style.configure('TNotebook.Tab',          background=BG3, foreground=TEXT2,
                         font=FONT_UI, padding=[14, 6], borderwidth=0)
        style.map('TNotebook.Tab',
                  background=[('selected', BG2)],
                  foreground=[('selected', ACCENT)])
        style.configure('Treeview',               background=BG2, foreground=TEXT,
                         fieldbackground=BG2,     rowheight=22,   font=FONT_MONO_S,
                         borderwidth=0)
        style.configure('Treeview.Heading',       background=BG3, foreground=ACCENT2,
                         font=('Courier New', 9, 'bold'), borderwidth=0)
        style.map('Treeview', background=[('selected', BG3)])
        style.configure('TScrollbar',             background=BG3, troughcolor=BG,
                         arrowcolor=TEXT2, borderwidth=0)
        style.configure('TProgressbar',           background=ACCENT, troughcolor=BG3,
                         borderwidth=0, thickness=4)

    # ── Layout ─────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header bar ──────────────────────────────────────────────────────
        hdr = tk.Frame(self.root, bg=BG3, height=54)
        hdr.pack(fill='x', side='top')
        hdr.pack_propagate(False)

        tk.Label(hdr, text='⚡ PYFORENSIX', bg=BG3, fg=ACCENT,
                 font=('Courier New', 16, 'bold')).pack(side='left', padx=20, pady=12)
        tk.Label(hdr, text='Forensic Analysis & Intrusion Detection',
                 bg=BG3, fg=TEXT2, font=FONT_MONO_S).pack(side='left', padx=4, pady=12)

        # Buttons
        btn_frame = tk.Frame(hdr, bg=BG3)
        btn_frame.pack(side='right', padx=12)

        self._btn_scan = self._hdr_btn(btn_frame, '▶  Full Scan', ACCENT,     self._run_scan)
        self._btn_rept = self._hdr_btn(btn_frame, '⬇  Export',    ACCENT2,    self._export_menu)
        self._hdr_btn(btn_frame, '✕  Clear',      TEXT2,     self._clear_all)

        # ── Risk banner ──────────────────────────────────────────────────────
        self._risk_frame = tk.Frame(self.root, bg=BG2, height=36)
        self._risk_frame.pack(fill='x')
        self._risk_frame.pack_propagate(False)
        self._risk_label = tk.Label(self._risk_frame, text='Threat Level: NOT SCANNED',
                                     bg=BG2, fg=TEXT2, font=('Courier New', 10, 'bold'))
        self._risk_label.pack(side='left', padx=18, pady=6)
        self._score_label = tk.Label(self._risk_frame, text='', bg=BG2, fg=TEXT2,
                                      font=FONT_MONO_S)
        self._score_label.pack(side='left', padx=8)
        self._progress = ttk.Progressbar(self._risk_frame, mode='indeterminate', length=200)
        self._progress.pack(side='right', padx=18, pady=10)

        # ── Notebook tabs ────────────────────────────────────────────────────
        self._nb = ttk.Notebook(self.root)
        self._nb.pack(fill='both', expand=True, padx=0, pady=0)

        self._tab_overview   = self._add_tab('📊 Overview')
        self._tab_processes  = self._add_tab('🔍 Processes')
        self._tab_network    = self._add_tab('🌐 Network')
        self._tab_files      = self._add_tab('📁 Files')
        self._tab_logs       = self._add_tab('📋 Logs')
        self._tab_alerts     = self._add_tab('🚨 Alerts')
        self._tab_raw        = self._add_tab('{ } Raw JSON')

        self._build_overview(self._tab_overview)
        self._build_processes(self._tab_processes)
        self._build_network(self._tab_network)
        self._build_files(self._tab_files)
        self._build_logs(self._tab_logs)
        self._build_alerts(self._tab_alerts)
        self._build_raw(self._tab_raw)

        # ── Status bar ───────────────────────────────────────────────────────
        sb = tk.Frame(self.root, bg=BG3, height=24)
        sb.pack(fill='x', side='bottom')
        sb.pack_propagate(False)
        self._status_var = tk.StringVar(value='')
        tk.Label(sb, textvariable=self._status_var, bg=BG3, fg=TEXT2,
                 font=('Courier New', 9), anchor='w').pack(side='left', padx=12, pady=3)
        tk.Label(sb, text=f'OS: {platform.system()} {platform.release()}',
                 bg=BG3, fg=TEXT2, font=('Courier New', 9)).pack(side='right', padx=12, pady=3)

    def _hdr_btn(self, parent, text, color, cmd):
        b = tk.Button(parent, text=text, bg=BG3, fg=color, activebackground=BG2,
                      activeforeground=color, font=('Courier New', 10, 'bold'),
                      bd=0, padx=14, pady=6, cursor='hand2', command=cmd,
                      relief='flat', highlightthickness=1, highlightbackground=BORDER)
        b.pack(side='left', padx=4, pady=10)
        return b

    def _add_tab(self, name: str) -> tk.Frame:
        frame = tk.Frame(self._nb, bg=BG)
        self._nb.add(frame, text=f'  {name}  ')
        return frame

    # ── Tab: Overview ──────────────────────────────────────────────────────────

    def _build_overview(self, parent: tk.Frame):
        parent.columnconfigure(0, weight=1)
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(1, weight=1)

        # Stat cards row
        cards = tk.Frame(parent, bg=BG)
        cards.grid(row=0, column=0, columnspan=2, sticky='ew', padx=16, pady=12)

        self._ov_cards = {}
        card_defs = [
            ('critical',  'CRITICAL',  RED,    '0'),
            ('high',      'HIGH',      ORANGE, '0'),
            ('medium',    'MEDIUM',    YELLOW, '0'),
            ('low',       'LOW',       GREEN,  '0'),
            ('processes', 'PROCESSES', BLUE,   '0'),
            ('ports',     'OPEN PORTS',ACCENT, '0'),
        ]
        for i, (key, label, color, val) in enumerate(card_defs):
            f = tk.Frame(cards, bg=BG3, relief='flat', bd=1)
            f.grid(row=0, column=i, padx=5, pady=4, sticky='ew')
            cards.columnconfigure(i, weight=1)
            v = tk.Label(f, text=val, bg=BG3, fg=color,
                         font=('Courier New', 24, 'bold'))
            v.pack(pady=(10, 2))
            tk.Label(f, text=label, bg=BG3, fg=TEXT2,
                     font=('Courier New', 8)).pack(pady=(0, 10))
            self._ov_cards[key] = v

        # System info panel
        left = tk.Frame(parent, bg=BG)
        left.grid(row=1, column=0, sticky='nsew', padx=(16, 6), pady=(0, 12))
        self._label(left, 'SYSTEM INFO').pack(anchor='w', padx=4, pady=(0, 6))
        self._sysinfo_text = scrolledtext.ScrolledText(
            left, bg=BG2, fg=TEXT, font=FONT_MONO_S,
            insertbackground=ACCENT, bd=0, relief='flat',
            wrap='word', state='disabled')
        self._sysinfo_text.pack(fill='both', expand=True)

        # Alerts summary
        right = tk.Frame(parent, bg=BG)
        right.grid(row=1, column=1, sticky='nsew', padx=(6, 16), pady=(0, 12))
        self._label(right, 'TOP ALERTS').pack(anchor='w', padx=4, pady=(0, 6))
        self._top_alerts_tree = self._tree(right,
            columns=('sev', 'category', 'title'),
            headings=('Severity', 'Category', 'Title'),
            widths=(80, 90, 340))
        self._top_alerts_tree.pack(fill='both', expand=True)
        self._tag_severity(self._top_alerts_tree)

    # ── Tab: Processes ─────────────────────────────────────────────────────────

    def _build_processes(self, parent: tk.Frame):
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

        toolbar = tk.Frame(parent, bg=BG)
        toolbar.grid(row=0, column=0, sticky='ew')
        tk.Label(toolbar, text='Filter:', bg=BG, fg=TEXT2, font=FONT_MONO_S).pack(side='left', padx=(12, 4), pady=6)
        self._proc_filter = tk.StringVar()
        self._proc_filter.trace('w', lambda *a: self._filter_processes())
        tk.Entry(toolbar, textvariable=self._proc_filter, bg=BG3, fg=TEXT,
                 insertbackground=ACCENT, font=FONT_MONO_S, bd=0, relief='flat',
                 width=24).pack(side='left', pady=6)
        tk.Label(toolbar, text='  Show suspicious only:', bg=BG, fg=TEXT2, font=FONT_MONO_S).pack(side='left')
        self._proc_susp_only = tk.BooleanVar()
        tk.Checkbutton(toolbar, variable=self._proc_susp_only, bg=BG, fg=ACCENT,
                       activebackground=BG, selectcolor=BG3,
                       command=self._filter_processes).pack(side='left')

        frame = tk.Frame(parent, bg=BG)
        frame.grid(row=1, column=0, sticky='nsew', padx=12, pady=(0, 8))
        parent.rowconfigure(1, weight=1)

        self._proc_tree = self._tree(frame,
            columns=('sev','pid','name','user','exe','flags'),
            headings=('Sev','PID','Process','User','Executable','Flags'),
            widths=(70,55,130,100,280,220))
        self._proc_tree.pack(fill='both', expand=True)
        self._tag_severity(self._proc_tree)

    # ── Tab: Network ───────────────────────────────────────────────────────────

    def _build_network(self, parent: tk.Frame):
        parent.rowconfigure(1, weight=1)
        parent.columnconfigure(0, weight=1)

        tk.Label(parent, text='ACTIVE CONNECTIONS', bg=BG, fg=ACCENT2,
                 font=('Courier New', 9, 'bold')).grid(row=0, column=0, sticky='w', padx=14, pady=(10, 4))

        frame = tk.Frame(parent, bg=BG)
        frame.grid(row=1, column=0, sticky='nsew', padx=12, pady=(0, 6))

        self._conn_tree = self._tree(frame,
            columns=('sev','pid','proc','laddr','raddr','status','flags'),
            headings=('Sev','PID','Process','Local','Remote','Status','Flags'),
            widths=(70,55,110,160,160,90,250))
        self._conn_tree.pack(fill='both', expand=True)
        self._tag_severity(self._conn_tree)

        tk.Label(parent, text='LISTENING PORTS', bg=BG, fg=ACCENT2,
                 font=('Courier New', 9, 'bold')).grid(row=2, column=0, sticky='w', padx=14, pady=(8, 4))

        frame2 = tk.Frame(parent, bg=BG)
        frame2.grid(row=3, column=0, sticky='ew', padx=12, pady=(0, 8))

        self._ports_tree = self._tree(frame2,
            columns=('port','ip','proc','pid','note'),
            headings=('Port','IP','Process','PID','Note'),
            widths=(60,120,140,55,300), height=8)
        self._ports_tree.pack(fill='x')

    # ── Tab: Files ─────────────────────────────────────────────────────────────

    def _build_files(self, parent: tk.Frame):
        parent.rowconfigure(1, weight=1)
        parent.columnconfigure(0, weight=1)

        ctrl = tk.Frame(parent, bg=BG)
        ctrl.grid(row=0, column=0, sticky='ew', padx=12, pady=8)
        tk.Label(ctrl, text='Recently modified (last N hours):', bg=BG, fg=TEXT2,
                 font=FONT_MONO_S).pack(side='left')
        self._file_hours = tk.StringVar(value='24')
        tk.Entry(ctrl, textvariable=self._file_hours, bg=BG3, fg=TEXT,
                 font=FONT_MONO_S, width=5, bd=0).pack(side='left', padx=6)
        tk.Button(ctrl, text='Scan Now', bg=BG3, fg=ACCENT, font=FONT_MONO_S,
                  bd=0, relief='flat', cursor='hand2',
                  command=self._scan_files_only).pack(side='left', padx=8)

        frame = tk.Frame(parent, bg=BG)
        frame.grid(row=1, column=0, sticky='nsew', padx=12, pady=(0, 8))

        self._file_tree = self._tree(frame,
            columns=('mtime','path','size','ext','flags'),
            headings=('Modified','Path','Size','Ext','Flags'),
            widths=(140,360,80,50,200))
        self._file_tree.pack(fill='both', expand=True)

    # ── Tab: Logs ──────────────────────────────────────────────────────────────

    def _build_logs(self, parent: tk.Frame):
        parent.rowconfigure(1, weight=1)
        parent.columnconfigure(0, weight=1)

        tk.Label(parent, text='LOG INDICATORS', bg=BG, fg=ACCENT2,
                 font=('Courier New', 9, 'bold')).grid(row=0, column=0, sticky='w', padx=14, pady=(10, 4))

        frame = tk.Frame(parent, bg=BG)
        frame.grid(row=1, column=0, sticky='nsew', padx=12)

        self._log_tree = self._tree(frame,
            columns=('sev','pattern','source','ts','raw'),
            headings=('Sev','Pattern','Source','Timestamp','Log Entry'),
            widths=(70,160,160,130,400))
        self._log_tree.pack(fill='both', expand=True)
        self._tag_severity(self._log_tree)

        tk.Label(parent, text='BRUTE FORCE SOURCES', bg=BG, fg=ACCENT2,
                 font=('Courier New', 9, 'bold')).grid(row=2, column=0, sticky='w', padx=14, pady=(8, 4))

        frame2 = tk.Frame(parent, bg=BG)
        frame2.grid(row=3, column=0, sticky='ew', padx=12, pady=(0, 8))
        self._bf_tree = self._tree(frame2,
            columns=('ip','attempts','sev'),
            headings=('Source IP','Attempts','Severity'),
            widths=(160,80,80), height=6)
        self._bf_tree.pack(fill='x')
        self._tag_severity(self._bf_tree)

    # ── Tab: Alerts ────────────────────────────────────────────────────────────

    def _build_alerts(self, parent: tk.Frame):
        parent.rowconfigure(0, weight=3)
        parent.rowconfigure(1, weight=2)
        parent.columnconfigure(0, weight=1)

        frame = tk.Frame(parent, bg=BG)
        frame.grid(row=0, column=0, sticky='nsew', padx=12, pady=(8, 4))

        self._alert_tree = self._tree(frame,
            columns=('sev','category','title','flags'),
            headings=('Severity','Category','Finding','Flags'),
            widths=(80,100,440,280))
        self._alert_tree.pack(fill='both', expand=True)
        self._tag_severity(self._alert_tree)
        self._alert_tree.bind('<<TreeviewSelect>>', self._on_alert_select)

        # Detail panel
        detail = tk.Frame(parent, bg=BG2)
        detail.grid(row=1, column=0, sticky='nsew', padx=12, pady=(0, 8))
        tk.Label(detail, text='ALERT DETAIL', bg=BG2, fg=ACCENT2,
                 font=('Courier New', 9, 'bold')).pack(anchor='w', padx=10, pady=(8, 4))
        self._alert_detail = scrolledtext.ScrolledText(
            detail, bg=BG2, fg=TEXT, font=FONT_MONO_S,
            insertbackground=ACCENT, bd=0, relief='flat',
            wrap='word', state='disabled', height=8)
        self._alert_detail.pack(fill='both', expand=True, padx=8, pady=(0, 8))

    # ── Tab: Raw JSON ──────────────────────────────────────────────────────────

    def _build_raw(self, parent: tk.Frame):
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        self._raw_text = scrolledtext.ScrolledText(
            parent, bg=BG2, fg=TEXT, font=('Courier New', 9),
            insertbackground=ACCENT, bd=0, relief='flat',
            wrap='none', state='disabled')
        self._raw_text.grid(row=0, column=0, sticky='nsew', padx=12, pady=8)

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _label(self, parent, text: str) -> tk.Label:
        return tk.Label(parent, text=text, bg=BG, fg=ACCENT2,
                        font=('Courier New', 9, 'bold'))

    def _tree(self, parent, columns, headings, widths, height=None) -> ttk.Treeview:
        frame = tk.Frame(parent, bg=BG)
        frame.pack(fill='both', expand=True if height is None else False)

        kw = {}
        if height:
            kw['height'] = height

        tv = ttk.Treeview(frame, columns=columns, show='headings',
                          selectmode='browse', **kw)
        vsb = ttk.Scrollbar(frame, orient='vertical', command=tv.yview)
        hsb = ttk.Scrollbar(frame, orient='horizontal', command=tv.xview)
        tv.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        for col, hd, w in zip(columns, headings, widths):
            tv.heading(col, text=hd, anchor='w')
            tv.column(col, width=w, minwidth=40, anchor='w')

        tv.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        return tv

    def _tag_severity(self, tv: ttk.Treeview):
        tv.tag_configure('sev_crit', foreground=RED)
        tv.tag_configure('sev_high', foreground=ORANGE)
        tv.tag_configure('sev_med',  foreground=YELLOW)
        tv.tag_configure('sev_low',  foreground=GREEN)
        tv.tag_configure('sev_ok',   foreground=TEXT2)

    def _status(self, msg: str):
        ts = datetime.now().strftime('%H:%M:%S')
        self._status_var.set(f'[{ts}]  {msg}')

    def _append_sysinfo(self, info: Dict):
        self._sysinfo_text.config(state='normal')
        self._sysinfo_text.delete('1.0', 'end')
        skip = {'disks'}
        for k, v in info.items():
            if k in skip:
                continue
            if isinstance(v, list):
                continue
            line = f'{k.replace("_", " ").upper():20s}  {v}\n'
            self._sysinfo_text.insert('end', line)
        self._sysinfo_text.config(state='disabled')

    # ── Scan orchestration ─────────────────────────────────────────────────────

    def _run_scan(self):
        if self._scanning:
            return
        self._scanning = True
        self._btn_scan.config(state='disabled', text='⏳ Scanning...')
        self._progress.start(12)
        self._status('Starting full forensic scan...')
        threading.Thread(target=self._do_scan, daemon=True).start()

    def _do_scan(self):
        try:
            from forensics.core.system_info      import get_system_info, get_logged_in_users, get_startup_items
            from forensics.core.process_scanner  import scan_processes
            from forensics.core.network_scanner  import scan_connections, scan_open_ports
            from forensics.core.file_scanner     import scan_recently_modified
            from forensics.core.log_analyzer     import scan_linux_logs, scan_windows_events, summarize_brute_force
            from forensics.core.intrusion_detector import build_report

            self._status('Collecting system info...')
            sysinfo   = get_system_info()
            users     = get_logged_in_users()
            startup   = get_startup_items()

            self._status('Scanning processes...')
            processes = scan_processes()

            self._status('Scanning network connections...')
            conns     = scan_connections()
            ports     = scan_open_ports()

            self._status('Scanning recently modified files...')
            try:
                hours = int(self._file_hours.get())
            except Exception:
                hours = 24
            files     = scan_recently_modified(hours=hours)

            self._status('Analyzing system logs...')
            if platform.system() == 'Windows':
                logs = scan_windows_events()
            else:
                logs = scan_linux_logs()
            brute = summarize_brute_force(logs)

            self._status('Building intrusion report...')
            report = build_report(
                processes=processes,
                connections=conns,
                open_ports=ports,
                recent_files=files,
                log_entries=logs,
                brute_force=brute,
                startup=startup,
            )

            self._scan_results = {
                'system':    sysinfo,
                'users':     users,
                'startup':   startup,
                'processes': processes,
                'conns':     conns,
                'ports':     ports,
                'files':     files,
                'logs':      logs,
                'brute':     brute,
                'report':    report.to_dict(),
            }
            self._report = report

            self.root.after(0, self._populate_ui)

        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            self.root.after(0, lambda: messagebox.showerror('Scan Error', f'{e}\n\n{tb}'))
        finally:
            self.root.after(0, self._scan_done)

    def _scan_done(self):
        self._scanning = False
        self._progress.stop()
        self._btn_scan.config(state='normal', text='▶  Full Scan')
        self._status('Scan complete.')

    def _populate_ui(self):
        r = self._scan_results
        rd = r.get('report', {})

        # Risk banner
        risk  = rd.get('risk_level', 'UNKNOWN')
        score = rd.get('score', 0)
        color = RISK_BADGE_COLORS.get(risk, TEXT2)
        self._risk_label.config(text=f'▸ Threat Level: {risk}', fg=color)
        self._score_label.config(text=f'  Threat Score: {score}', fg=TEXT2)

        # Overview cards
        sm = rd.get('summary', {})
        self._ov_cards['critical'].config(text=str(sm.get('CRITICAL', 0)))
        self._ov_cards['high'].config(text=str(sm.get('HIGH', 0)))
        self._ov_cards['medium'].config(text=str(sm.get('MEDIUM', 0)))
        self._ov_cards['low'].config(text=str(sm.get('LOW', 0)))
        self._ov_cards['processes'].config(text=str(len(r.get('processes', []))))
        self._ov_cards['ports'].config(text=str(len(r.get('ports', []))))

        self._append_sysinfo(r.get('system', {}))

        # Top alerts preview
        self._top_alerts_tree.delete(*self._top_alerts_tree.get_children())
        for a in rd.get('alerts', [])[:30]:
            sev = a.get('severity', 'OK')
            self._top_alerts_tree.insert('', 'end',
                values=(sev, a.get('category', ''), a.get('title', '')[:80]),
                tags=(_sev_tag(sev),))

        # Processes
        self._proc_tree.delete(*self._proc_tree.get_children())
        for p in r.get('processes', []):
            sev = p['severity']
            self._proc_tree.insert('', 'end', values=(
                sev, p['pid'], p['name'], p['username'],
                p['exe'][:60] if p['exe'] else '', ' | '.join(p['flags'])
            ), tags=(_sev_tag(sev),))

        # Network
        self._conn_tree.delete(*self._conn_tree.get_children())
        for c in r.get('conns', []):
            sev = c['severity']
            self._conn_tree.insert('', 'end', values=(
                sev, c['pid'], c['process_name'],
                c['laddr'], c['raddr'], c['status'],
                ' | '.join(c['flags'])
            ), tags=(_sev_tag(sev),))

        self._ports_tree.delete(*self._ports_tree.get_children())
        for p in r.get('ports', []):
            tag = 'sev_high' if p.get('suspicious') else 'sev_ok'
            self._ports_tree.insert('', 'end', values=(
                p['port'], p['ip'], p['process_name'], p['pid'], p['note']
            ), tags=(tag,))

        # Files
        self._file_tree.delete(*self._file_tree.get_children())
        for f in r.get('files', []):
            tag = 'sev_med' if f.get('flags') else 'sev_ok'
            self._file_tree.insert('', 'end', values=(
                f['mtime'], f['path'][:80], f['size'], f['ext'],
                ' | '.join(f['flags'])
            ), tags=(tag,))

        # Logs
        self._log_tree.delete(*self._log_tree.get_children())
        for entry in r.get('logs', []):
            sev = entry.get('severity', 'MEDIUM')
            self._log_tree.insert('', 'end', values=(
                sev,
                entry.get('pattern', entry.get('event_id', '')),
                os.path.basename(str(entry.get('source', ''))),
                entry.get('timestamp', ''),
                entry.get('raw', entry.get('message', ''))[:120],
            ), tags=(_sev_tag(sev),))

        self._bf_tree.delete(*self._bf_tree.get_children())
        for bf in r.get('brute', []):
            sev = bf.get('severity', 'HIGH')
            self._bf_tree.insert('', 'end', values=(
                bf['ip'], bf['attempts'], sev
            ), tags=(_sev_tag(sev),))

        # All alerts
        self._alert_tree.delete(*self._alert_tree.get_children())
        self._alerts_data = rd.get('alerts', [])
        for a in self._alerts_data:
            sev = a.get('severity', 'OK')
            self._alert_tree.insert('', 'end', values=(
                sev,
                a.get('category', ''),
                a.get('title', '')[:80],
                ' | '.join(a.get('flags', []))[:60],
            ), tags=(_sev_tag(sev),))

        # Raw JSON
        self._raw_text.config(state='normal')
        self._raw_text.delete('1.0', 'end')
        self._raw_text.insert('end', json.dumps(r.get('report', {}), indent=2, default=str))
        self._raw_text.config(state='disabled')

        self._status(f'Scan complete — {sm.get("TOTAL", 0)} alerts | Risk: {risk} | Score: {score}')

    def _on_alert_select(self, event):
        sel = self._alert_tree.selection()
        if not sel:
            return
        idx = self._alert_tree.index(sel[0])
        if idx >= len(getattr(self, '_alerts_data', [])):
            return
        a = self._alerts_data[idx]
        detail = (
            f"SEVERITY:     {a.get('severity','')}\n"
            f"CATEGORY:     {a.get('category','')}\n"
            f"TITLE:        {a.get('title','')}\n"
            f"DETAIL:       {a.get('detail','')}\n"
            f"FLAGS:        {', '.join(a.get('flags',[]))}\n\n"
            f"MITRE ATT&CK:\n"
        )
        for t in a.get('techniques', []):
            detail += f"  {t['id']} — {t['name']}\n"
        detail += '\nREMEDIATION:\n'
        for r in a.get('remediation', []):
            if r:
                detail += f"  • {r}\n"
        self._alert_detail.config(state='normal')
        self._alert_detail.delete('1.0', 'end')
        self._alert_detail.insert('end', detail)
        self._alert_detail.config(state='disabled')

    def _filter_processes(self):
        query = self._proc_filter.get().lower()
        susp_only = self._proc_susp_only.get()
        for row in self._proc_tree.get_children():
            vals = [str(v).lower() for v in self._proc_tree.item(row, 'values')]
            match_query = not query or any(query in v for v in vals)
            match_susp  = not susp_only or vals[0] not in ('ok', '')
            if match_query and match_susp:
                self._proc_tree.reattach(row, '', 'end')
            else:
                self._proc_tree.detach(row)

    def _scan_files_only(self):
        self._status('Scanning files...')
        threading.Thread(target=self._do_files_scan, daemon=True).start()

    def _do_files_scan(self):
        from forensics.core.file_scanner import scan_recently_modified
        try:
            hours = int(self._file_hours.get())
        except Exception:
            hours = 24
        files = scan_recently_modified(hours=hours)
        self._scan_results['files'] = files
        self.root.after(0, lambda: self._refresh_files(files))

    def _refresh_files(self, files):
        self._file_tree.delete(*self._file_tree.get_children())
        for f in files:
            tag = 'sev_med' if f.get('flags') else 'sev_ok'
            self._file_tree.insert('', 'end', values=(
                f['mtime'], f['path'][:80], f['size'], f['ext'],
                ' | '.join(f['flags'])
            ), tags=(tag,))
        self._status(f'File scan complete — {len(files)} files found.')

    # ── Export ─────────────────────────────────────────────────────────────────

    def _export_menu(self):
        if not self._scan_results:
            messagebox.showwarning('No Data', 'Run a scan first.')
            return
        win = tk.Toplevel(self.root)
        win.title('Export Report')
        win.configure(bg=BG)
        win.geometry('280x200')
        win.resizable(False, False)
        tk.Label(win, text='Export Format', bg=BG, fg=ACCENT,
                 font=('Courier New', 12, 'bold')).pack(pady=16)
        for label, cmd in [('HTML Report', self._export_html),
                            ('JSON Report', self._export_json),
                            ('CSV Alerts',  self._export_csv)]:
            tk.Button(win, text=label, bg=BG3, fg=TEXT, font=FONT_UI,
                      bd=0, relief='flat', padx=20, pady=8, cursor='hand2',
                      command=lambda c=cmd, w=win: (w.destroy(), c())
                      ).pack(fill='x', padx=30, pady=4)

    def _export_html(self):
        from forensics.utils.reporter import generate_html_report
        path = filedialog.asksaveasfilename(defaultextension='.html',
            filetypes=[('HTML', '*.html')], initialfile='pyforensix_report.html')
        if path:
            out = generate_html_report(self._scan_results['report'],
                                       self._scan_results.get('system', {}), path)
            self._status(f'HTML report saved: {out}')
            messagebox.showinfo('Saved', f'Report saved to:\n{out}')

    def _export_json(self):
        from forensics.utils.reporter import generate_json_report
        path = filedialog.asksaveasfilename(defaultextension='.json',
            filetypes=[('JSON', '*.json')], initialfile='pyforensix_report.json')
        if path:
            out = generate_json_report(self._scan_results['report'],
                                       self._scan_results.get('system', {}), path)
            self._status(f'JSON report saved: {out}')

    def _export_csv(self):
        from forensics.utils.reporter import generate_csv_report
        path = filedialog.asksaveasfilename(defaultextension='.csv',
            filetypes=[('CSV', '*.csv')], initialfile='pyforensix_alerts.csv')
        if path:
            out = generate_csv_report(self._scan_results['report'].get('alerts', []), path)
            self._status(f'CSV saved: {out}')

    def _clear_all(self):
        self._scan_results = {}
        self._report = None
        for tv in [self._proc_tree, self._conn_tree, self._ports_tree,
                   self._file_tree, self._log_tree, self._bf_tree,
                   self._alert_tree, self._top_alerts_tree]:
            tv.delete(*tv.get_children())
        self._raw_text.config(state='normal')
        self._raw_text.delete('1.0', 'end')
        self._raw_text.config(state='disabled')
        self._alert_detail.config(state='normal')
        self._alert_detail.delete('1.0', 'end')
        self._alert_detail.config(state='disabled')
        self._sysinfo_text.config(state='normal')
        self._sysinfo_text.delete('1.0', 'end')
        self._sysinfo_text.config(state='disabled')
        self._risk_label.config(text='Threat Level: NOT SCANNED', fg=TEXT2)
        self._score_label.config(text='')
        for v in self._ov_cards.values():
            v.config(text='0')
        self._status('Cleared.')


RISK_BADGE_COLORS = {
    'CRITICAL': RED,
    'HIGH':     ORANGE,
    'MEDIUM':   YELLOW,
    'LOW':      GREEN,
    'CLEAN':    GREEN,
}


def run_gui():
    root = tk.Tk()
    app = PyForensixGUI(root)
    root.mainloop()


if __name__ == '__main__':
    run_gui()
