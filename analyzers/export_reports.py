"""Export report generator — /export command for HTML/Markdown/JSON dossiers.

Usage:
    /export dossier <nick> [format]  — export user dossier
    /export channel <#channel> [fmt] — export channel stats
    /export heatmap <#channel> [fmt] — export activity heatmap
    /export ai [format]              — export AI detection report
    Formats: html (default), md, json
"""

import json
import os
import time

__plugin_name__ = "Export Reports"
__plugin_version__ = "1.0"
__plugin_author__ = "eyearesee"
__plugin_desc__ = "Export dossiers, stats, and reports to files"

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_EXPORT_DIR = os.path.join(_SCRIPT_DIR, "exports")


def _ensure_export_dir():
    os.makedirs(_EXPORT_DIR, exist_ok=True)


def _format_dossier_html(dossier: dict) -> str:
    lines = ['<html><head><meta charset="utf-8"><title>Dossier</title>',
             '<style>body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:20px}',
             'h1{color:#00bcd4} h2{color:#ff9800} .badge{display:inline-block;margin:2px;padding:2px 6px;background:#333;border-radius:3px}',
             '.bar{background:#333;height:12px;border-radius:6px} .fill{height:100%;border-radius:6px;background:linear-gradient(90deg,#4caf50,#8bc34a)}',
             'table{border-collapse:collapse;width:100%} td,th{border:1px solid #444;padding:4px 8px} th{background:#333}</style></head><body>']
    lines.append(f'<h1>Dossier: {dossier.get("nick","?")}</h1>')
    p = dossier.get("personality", {})
    if p and p.get("confidence") not in ("insufficient data", "", None):
        lines.append('<h2>Personality (Big Five)</h2>')
        for trait in ["openness","conscientiousness","extraversion","agreeableness","neuroticism"]:
            v = p.get(trait, 50)
            lines.append(f'<p>{trait.capitalize()}: {v}% <span class="bar"><span class="fill" style="width:{v}%"></span></span></p>')
        lines.append(f'<p>Samples: {p.get("samples",0)} | Confidence: {p.get("confidence","")}</p>')
    r = dossier.get("role")
    if r:
        lines.append('<h2>Role</h2>')
        lines.append(f'<p>Primary: <b>{r.get("primary_role","?")}</b></p>')
        scores = r.get("scores", {})
        if scores:
            lines.append('<table><tr><th>Role</th><th>Score</th></tr>')
            for role, score in sorted(scores.items(), key=lambda x: -x[1])[:5]:
                lines.append(f'<tr><td>{role}</td><td>{score:.0%}</td></tr>')
            lines.append('</table>')
    e = dossier.get("emotion", {})
    if e:
        lines.append(f'<h2>Emotion</h2><p>Dominant: {e.get("most_common_emotion","?")} | Volatility: {e.get("volatility",0):.0%}</p>')
    bd = dossier.get("badges", [])
    if bd:
        lines.append('<h2>Badges</h2>')
        for b in bd:
            lines.append(f'<span class="badge">{b.get("icon","")} {b.get("name",b.get("id",""))}</span>')
    sa = dossier.get("sarcasm", {})
    if sa.get("total_analyzed", 0):
        lines.append(f'<h2>Sarcasm</h2><p>Rate: {sa["sarcasm_rate"]:.0%} of {sa["total_analyzed"]} msgs</p>')
    st_trend = dossier.get("sentiment_trend", {})
    if st_trend.get("sample_count", 0):
        lines.append(f'<h2>Sentiment</h2><p>{st_trend["avg_score"]:+.2f} [{st_trend.get("trend","?")}]</p>')
    lines.append('</body></html>')
    return '\n'.join(lines)


def _format_dossier_md(dossier: dict) -> str:
    lines = [f'# Dossier: {dossier.get("nick","?")}']
    p = dossier.get("personality", {})
    if p and p.get("confidence") not in ("insufficient data", "", None):
        lines.append(f'\n## Personality (Big Five)  ({p.get("samples",0)} msgs, {p.get("confidence","")})')
        for trait in ["openness","conscientiousness","extraversion","agreeableness","neuroticism"]:
            v = p.get(trait, 50)
            bar = '█' * (v // 10) + '░' * (10 - v // 10)
            lines.append(f'- {trait.capitalize():<20} {bar} {v}%')
    r = dossier.get("role")
    if r:
        lines.append(f'\n## Role: {r.get("primary_role","?")}')
    e = dossier.get("emotion", {})
    if e:
        lines.append(f'\n## Emotion: {e.get("most_common_emotion","?")} (volatility {e.get("volatility",0):.0%})')
    bd = dossier.get("badges", [])
    if bd:
        lines.append('\n## Badges')
        for b in bd:
            lines.append(f'- {b.get("icon","")} {b.get("name",b.get("id",""))}')
    return '\n'.join(lines)


def _format_channel_html(channel: str, stats: dict, hm: dict) -> str:
    lines = ['<html><head><meta charset="utf-8"><title>Channel Stats</title>',
             '<style>body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:20px}',
             'h1{color:#00bcd4} .heatmap{display:grid;grid-template-columns:repeat(24,1fr);gap:2px;width:100%}',
             '.cell{padding:4px;text-align:center;border-radius:2px;font-size:10px}',
             '</style></head><body>']
    lines.append(f'<h1>Channel: {channel}</h1>')
    lines.append(f'<p>Messages: {stats.get("total_msgs",0)} | Users: {stats.get("unique_users",0)}</p>')
    day_names = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
    max_c = max((c for d in hm.values() for c in d.values()), default=1)
    for d_idx in range(7):
        day_hm = hm.get(d_idx, {})
        cells = []
        for h in range(24):
            c = day_hm.get(h, 0)
            if c == 0:
                cells.append('<span class="cell" style="background:#222">·</span>')
            else:
                intensity = int(c / max_c * 4)
                colors = ["#1a3a1a","#2d5a2d","#4caf50","#8bc34a","#cddc39"]
                cells.append(f'<span class="cell" style="background:{colors[min(intensity,4)]}">{c}</span>')
        lines.append(f'<div style="margin:4px 0"><b>{day_names[d_idx]}</b></div><div class="heatmap">{"".join(cells)}</div>')
    lines.append('</body></html>')
    return '\n'.join(lines)


def setup(api):
    @api.command("export")
    def cmd_export(api, args):
        """Export reports to files. /export <type> <target> [format]"""
        tui = api._tui
        if tui is None:
            api.status("Export requires TUI context")
            return

        client = tui._active_client()
        parts = args.strip().split()
        if not parts:
            api.status("Usage: /export dossier|channel|heatmap|ai <target> [html|md|json]")
            return

        etype = parts[0].lower()
        target = parts[1] if len(parts) > 1 else ""
        fmt = parts[2].lower() if len(parts) > 2 else "html"
        if fmt not in ("html", "md", "json"):
            fmt = "html"

        _ensure_export_dir()
        ts = time.strftime("%Y%m%d_%H%M%S")

        if etype == "dossier":
            if not target:
                target = client.nick
            dossier = client.scoring.integrations.dashboard.build_dossier(target, client.scoring)
            if fmt == "html":
                content = _format_dossier_html(dossier)
                ext = "html"
            elif fmt == "md":
                content = _format_dossier_md(dossier)
                ext = "md"
            else:
                content = json.dumps(dossier, indent=2, ensure_ascii=False, default=str)
                ext = "json"
            fname = f"dossier_{target}_{ts}.{ext}"

        elif etype in ("channel", "heatmap"):
            if not target:
                tui_win = tui.get_current_window()
                target = tui_win.name if tui_win and tui_win.name.startswith("#") else ""
            if not target:
                api.status("Usage: /export channel <#channel>")
                return
            stats = client.scoring.channel_stats.get_stats(target)
            na = client.scoring.network_analytics
            hm = na.get_heatmap(target)
            if fmt == "html":
                content = _format_channel_html(target, stats, hm)
                ext = "html"
            elif fmt == "md":
                day_names = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
                lines = [f"# {target}", f"\nMessages: {stats.get('total_msgs',0)} | Users: {stats.get('unique_users',0)}"]
                for d in range(7):
                    row = ' '.join(str(hm.get(d, {}).get(h, 0) or '·') for h in range(24))
                    lines.append(f"\n**{day_names[d]}**  \n`{row}`")
                content = '\n'.join(lines)
                ext = "md"
            else:
                content = json.dumps({"channel": target, "stats": stats, "heatmap": {str(k): v for k, v in hm.items()}}, indent=2, default=str)
                ext = "json"
            fname = f"channel_{target.lstrip('#')}_{ts}.{ext}"

        elif etype == "ai":
            suspects = getattr(client.scoring.ai_detector, 'load_historical_suspects', lambda t: [])(70)
            if fmt == "html":
                lines = ['<html><head><meta charset="utf-8"><title>AI Detection Report</title>',
                         '<style>body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:20px}',
                         'h1{color:#f44336} table{border-collapse:collapse;width:100%}',
                         'td,th{border:1px solid #444;padding:4px 8px} th{background:#333}</style></head><body>',
                         '<h1>AI Detection Report</h1>',
                         '<table><tr><th>Nick</th><th>Avg Score</th><th>Msgs</th><th>Channels</th></tr>']
                for s in suspects[:50]:
                    lines.append(f'<tr><td>{s["nick"]}</td><td>{s["avg_score"]:.0f}%</td><td>{s["msg_count"]}</td><td>{", ".join(s.get("channels",[]))}</td></tr>')
                lines.append('</table></body></html>')
                content = '\n'.join(lines)
                ext = "html"
            elif fmt == "md":
                lines = ['# AI Detection Report', '', '| Nick | Avg Score | Msgs | Channels |', '|------|-----------|------|----------|']
                for s in suspects[:50]:
                    lines.append(f'| {s["nick"]} | {s["avg_score"]:.0f}% | {s["msg_count"]} | {", ".join(s.get("channels",[]))} |')
                content = '\n'.join(lines)
                ext = "md"
            else:
                content = json.dumps(suspects[:50], indent=2, default=str)
                ext = "json"
            fname = f"ai_report_{ts}.{ext}"

        else:
            api.status(f"Unknown export type: {etype}. Use dossier|channel|heatmap|ai")
            return

        fpath = os.path.join(_EXPORT_DIR, fname)
        try:
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(content)
            api.status(f"Exported to: {fpath}")
        except Exception as e:
            api.status(f"Export failed: {e}")
