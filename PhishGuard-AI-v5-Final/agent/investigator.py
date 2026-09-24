class PhishGuardAgent:
    """Deterministic defensive investigation orchestrator; no autonomous exploitation."""
    def __init__(self, console=None): self.console=console
    def step(self,message):
        if self.console: self.console.print(f"[cyan][AGENT][/cyan] {message}")
    def investigate(self, url, runner):
        self.step("Starting autonomous defensive investigation")
        result=runner(url, console=self.console, agent=self)
        self.step("Correlating multi-layer evidence")
        result["agent"]={"mode":"autonomous-defensive","steps":"URL → network → website → ML → reputation → risk correlation"}
        return result
