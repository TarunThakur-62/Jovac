from rich.console import Console
from rich.prompt import Prompt
from utils.ui import banner, show_result, show_history, show_module, show_menu
from core.analyzer import analyze_target
from core.ml_engine import predict_url, model_status
from agent.investigator import PhishGuardAgent
from checks.qr_checks import extract_qr_url
from checks.network_checks import dns_and_tls, domain_age
from checks.content_checks import fetch_and_analyze
from checks.threat_intel import check_threat_intelligence
from reports.generator import generate_reports, list_reports
from urllib.parse import urlsplit
console=Console()

def ask_url():
    return Prompt.ask("\n[bold cyan]Enter Target URL[/bold cyan]").strip()

def full_scan(url, agent_mode=False):
    console.print("\n[bold cyan]╔══════════════════════════════════════════════╗[/bold cyan]\n║      🤖 PHISHGUARD-AI v5.0 SCAN ENGINE      ║\n╚══════════════════════════════════════════════╝[/bold cyan]")
    console.print(f"\n[bold]Target:[/bold] [cyan]{url}[/cyan]\n")
    try:
        if agent_mode:
            result=PhishGuardAgent(console).investigate(url,analyze_target)
        else:
            result=analyze_target(url,console=console)
        console.print("\n[yellow]📄 Generating Automatic Security Reports...[/yellow]")
        paths=generate_reports(result)
        console.print("[green]✓ JSON Report Generated\n✓ TXT Report Generated\n✓ PDF Report Generated[/green]")
        show_result(result)
        console.print("\n[bold green]Reports Saved Successfully:[/bold green]")
        for k,p in paths.items(): console.print(f"  [cyan]{k.upper()}:[/cyan] {p}")
    except Exception as e: console.print(f"[bold red]Scan Error:[/bold red] {e}")

def ml_scan():
    show_module("🤖 MACHINE LEARNING PHISHING CLASSIFICATION"); url=ask_url()
    try:
        p=predict_url(url)
        console.print(f"\nModel: {p['model']}\nPrediction: {'🚨 PHISHING' if p['label']=='PHISHING' else '✅ LEGITIMATE'}\nML Confidence: {p['confidence']:.2f}%\nPhishing Probability: {p['phishing_probability']:.2f}%\n[dim]{model_status()}[/dim]")
    except Exception as e: console.print(f"[red]ML Error: {e}[/red]")

def network_scan():
    show_module("🌐 DOMAIN & NETWORK INTELLIGENCE"); url=ask_url(); host=urlsplit(url).hostname or ""
    try:
        n=dns_and_tls(host); a=domain_age(host)
        console.print(f"\nDomain: {host}\nIP: {n.get('ips',[])}\nTLS: {n.get('tls',{})}\nDomain Age: {a.get('age_days','Unknown')} days")
    except Exception as e: console.print(f"[red]Network Error: {e}[/red]")

def behaviour_scan():
    show_module("🧠 WEBSITE BEHAVIOUR ANALYSIS"); r=fetch_and_analyze(ask_url()); s=r["signals"]
    for k,v in s.items(): console.print(f"{k}: {v}")
    console.print(f"\nFinal URL: {r.get('final_url')}\nRedirects: {len(r.get('redirect_chain',[]))}")

def qr_scan():
    show_module("📱 QR / QUISHING SCANNER"); path=Prompt.ask("QR image path")
    try:
        url=extract_qr_url(path); console.print(f"[green]✓ Extracted:[/green] {url}")
        if Prompt.ask("Run full scan?",choices=["y","n"],default="y")=="y": full_scan(url)
    except Exception as e: console.print(f"[red]QR Error: {e}[/red]")

def ti_scan():
    show_module("🛡 THREAT INTELLIGENCE LOOKUP"); r=check_threat_intelligence(ask_url())
    for k,v in r.items():
        if k!="evidence": console.print(f"{k}: {v}")

def single_feature(name, fn):
    show_module(name)
    try:
        r=fn(ask_url())
        console.print_json(data=r)
    except Exception as e: console.print(f"[red]Error: {e}[/red]")

def main():
    while True:
        banner(); show_menu()
        choice=Prompt.ask("\n[bold cyan]PhishGuard-AI[/bold cyan] > Select Module",
                          choices=[str(i) for i in range(16)]+["0"],default="1")
        if choice=="0": console.print("[bold red]PhishGuard-AI terminated.[/bold red]"); break
        if choice=="1": full_scan(ask_url())
        elif choice=="2": full_scan(ask_url(),True)
        elif choice=="3": ml_scan()
        elif choice=="4": single_feature("🔗 ADVANCED URL ANALYSIS",lambda u: __import__("checks.url_checks",fromlist=["url_checks"]).url_checks(u))
        elif choice=="5": network_scan()
        elif choice=="6": single_feature("🔒 SSL / HTTPS ANALYSIS",lambda u: dns_and_tls(urlsplit(u if "://" in u else "https://"+u).hostname or ""))
        elif choice=="7": single_feature("🔄 REDIRECT ANALYSIS",fetch_and_analyze)
        elif choice=="8": behaviour_scan()
        elif choice=="9": single_feature("🔐 CREDENTIAL FORM ANALYSIS",fetch_and_analyze)
        elif choice=="10": single_feature("🧠 SUSPICIOUS BEHAVIOUR ANALYSIS",fetch_and_analyze)
        elif choice=="11": single_feature("🏢 BRAND IMPERSONATION ANALYSIS",lambda u: __import__("checks.brand_checks",fromlist=["brand_checks"]).brand_checks(urlsplit(u if "://" in u else "https://"+u).hostname or ""))
        elif choice=="12": qr_scan()
        elif choice=="13": ti_scan()
        elif choice=="14": console.print("[yellow]Browser extension is in extension/ and calls the optional FastAPI server.[/yellow]")
        elif choice=="15": show_history(); console.print("\n[bold]Reports:[/bold]\n"+list_reports())
        input("\nPress ENTER to return to main menu...")
if __name__=="__main__": main()
