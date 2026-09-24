import os,json
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
console=Console()
def banner():
    os.system("clear")
    console.print(Panel(Text.from_markup("[bold cyan]🛡 PHISHGUARD-AI v5.0[/bold cyan]\n[bold white]Intelligent Hybrid Phishing URL & Website Detection[/bold white]\n[dim cyan]ML • AI Agent • URL • DNS • SSL • Behaviour • Threat Intel[/dim cyan]"),border_style="bright_cyan",padding=(1,4),expand=False))
def show_menu():
    t=Table(title="⚡ PHISHGUARD-AI CONTROL PANEL ⚡",border_style="cyan",header_style="bold cyan",expand=False)
    t.add_column("OPTION",justify="center",style="bold cyan"); t.add_column("MODULE",style="white")
    rows=["🔍 Full Hybrid Website Scan","🤖 AI Agent Investigation Mode","🧠 ML Phishing Classification","🔗 Advanced URL Feature Analysis","🌐 DNS & Domain Intelligence","🔒 SSL / HTTPS Analysis","🔄 Redirect Chain Analysis","🌍 Website Content Analysis","🔐 Login & Credential Form Detection","🧠 Suspicious Behaviour Detection","🏢 Brand Impersonation Detection","📱 QR / Quishing Scanner","🛡 Threat Intelligence Lookup","🌐 Browser Extension Scanner","📊 Scan History & Reports"]
    for i,x in enumerate(rows,1): t.add_row(f"{i:02d}",x)
    t.add_row("00","❌ Exit"); console.print(t)
def show_module(name): console.print(Panel.fit(f"[bold cyan]{name}[/bold cyan]",border_style="bright_cyan",padding=(1,3)))
def show_result(r):
    console.print(Panel.fit("[bold cyan]FINAL SECURITY ANALYSIS[/bold cyan]",border_style="bright_cyan"))
    console.print(f"\nTarget: [cyan]{r.get('target')}[/cyan]\nRisk Score: [bold]{r.get('risk_score')}/100[/bold]")
    ml=r.get("ml",{}); console.print(f"ML Prediction: {'[red]🚨 PHISHING[/red]' if ml.get('label')=='PHISHING' else '[green]✅ LEGITIMATE[/green]'}\nML Confidence: {ml.get('confidence',0):.2f}%")
    b=r.get("brand",{}); console.print(f"Official Domains Verified: {', '.join(b.get('official_matches',[])) or 'None'}")
    console.print(f"Brand Impersonation Signals: {b.get('matches') or 'None'}")
    console.print(f"Domain Age: {r.get('domain_age',{}).get('age_days','Unknown')} Days")
    console.print(f"Likely Attack Purpose: [yellow]{r.get('intent',{}).get('likely_purpose')}[/yellow]")
    v=r.get("verdict","UNKNOWN"); console.print(Panel.fit(("🚨 " if "PHISHING" in v else "⚠ " if "SUSPICIOUS" in v else "✅ ")+v,border_style="red" if "PHISHING" in v else "yellow" if "SUSPICIOUS" in v else "green"))
    ev=r.get("evidence",[])
    if ev:
        t=Table(title="SECURITY EVIDENCE",border_style="cyan",header_style="bold cyan"); t.add_column("SEVERITY"); t.add_column("FINDING")
        for e in ev: t.add_row(str(e.get("severity","info")).upper(),str(e.get("message","")))
        console.print(t)
    console.print(Panel("• Never enter credentials on an untrusted site.\n• Verify important domains independently.\n• Treat ML confidence as model output, not a guarantee.\n• Only scan systems/URLs you are authorized to assess.",title="RECOMMENDATION",border_style="yellow"))
def show_history():
    f=os.path.join(os.path.dirname(os.path.dirname(__file__)),"reports","output","history.jsonl")
    console.print(Panel.fit("[bold cyan]📊 SCAN HISTORY[/bold cyan]",border_style="cyan"))
    if not os.path.exists(f): console.print("[yellow]No history.[/yellow]"); return
    t=Table(title="Previous Security Scans",border_style="cyan",header_style="bold cyan"); [t.add_column(x) for x in ["TIME","TARGET","SCORE","VERDICT"]]
    try:
        with open(f,encoding="utf8") as h:
            for line in h:
                try:
                    d=json.loads(line); t.add_row(str(d.get("time","N/A")),str(d.get("target","N/A")),str(d.get("score","N/A")),str(d.get("verdict","N/A")))
                except json.JSONDecodeError: continue
        console.print(t)
    except Exception as e: console.print(f"[red]History Error: {e}[/red]")
