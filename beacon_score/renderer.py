"""
Terminal output renderer using Rich.
Produces a ranked findings table plus per-candidate signal breakdown panels.
"""

import json
from datetime import datetime
from .engine import BeaconCandidate


CONFIDENCE_COLORS = {
    "CRITICAL":     "bold red",
    "HIGH":         "red",
    "MEDIUM":       "yellow",
    "LOW":          "cyan",
    "INFORMATIONAL":"dim white",
}

SIGNAL_BAR_WIDTH = 20


def _score_bar(score: float, width: int = SIGNAL_BAR_WIDTH) -> str:
    filled = int(score * width)
    bar = "█" * filled + "░" * (width - filled)
    return bar


def _ts_to_human(ts_str: str) -> str:
    try:
        ts = float(ts_str)
        if ts <= 0:
            return "unknown"
        return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts_str or "unknown"


BANNER = r"""
  _                                                                        
 | |__   ___  __ _  ___  ___  _ __       ___  ___  ___  _ __  ___        
 | '_ \ / _ \/ _` |/ __|/ _ \| '_ \     / __|/ __|/ _ \| '__|/ _ \       
 | |_) |  __/ (_| | (__| (_) | | | |    \__ \ (__|  (_) | |  |  __/      
 |_.__/ \___|\__,_|\___|\___/|_| |_|    |___/\___|\___/|_|   \___|       

  Multi-signal C2 beacon detector  •  NorthQuinn Inc.
"""


def render_summary_table(candidates: list[BeaconCandidate], console=None):
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
    except ImportError:
        _fallback_summary(candidates)
        return

    if console is None:
        console = Console()

    console.print(f"[bold cyan]{BANNER}[/bold cyan]")

    table = Table(
        title="[bold]beacon-score[/bold] — C2 Beacon Candidates",
        box=box.MINIMAL_DOUBLE_HEAD,
        show_lines=False,
        title_style="bold white",
        header_style="bold cyan",
        border_style="dim white",
    )

    table.add_column("#",          style="dim",        width=4,  justify="right")
    table.add_column("Destination", style="white",     min_width=16)
    table.add_column("Score",       style="white",     width=8,  justify="right")
    table.add_column("Confidence",  style="white",     width=14)
    table.add_column("Sessions",    style="dim white", width=10, justify="right")
    table.add_column("Ports",       style="dim white", width=14)
    table.add_column("ATT&CK",      style="dim cyan",  min_width=20)
    table.add_column("First Seen",  style="dim",       width=20)

    for i, c in enumerate(candidates, 1):
        color = CONFIDENCE_COLORS.get(c.confidence, "white")
        ports_str = ",".join(str(p) for p in sorted(c.ports)[:5])
        if len(c.ports) > 5:
            ports_str += "…"
        attack_str = " ".join(t["id"] for t in c.attack_techniques[:4])
        table.add_row(
            str(i),
            c.destination,
            f"[{color}]{c.total_score:.4f}[/{color}]",
            f"[{color}]{c.confidence}[/{color}]",
            str(c.connection_count),
            ports_str,
            attack_str,
            _ts_to_human(c.first_seen),
        )

    console.print()
    console.print(table)
    console.print()


def render_candidate_detail(candidate: BeaconCandidate, console=None):
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich import box
        from rich.text import Text
    except ImportError:
        _fallback_detail(candidate)
        return

    if console is None:
        console = Console()

    color = CONFIDENCE_COLORS.get(candidate.confidence, "white")

    header = (
        f"[bold white]{candidate.destination}[/bold white]  "
        f"[{color}]{candidate.confidence}[/{color}]  "
        f"score=[{color}]{candidate.total_score:.4f}[/{color}]  "
        f"sessions=[dim]{candidate.connection_count}[/dim]  "
        f"ports=[dim]{','.join(str(p) for p in sorted(candidate.ports))}[/dim]"
    )

    sig_table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
    sig_table.add_column("Signal",   style="white",     min_width=22)
    sig_table.add_column("Score",    style="white",     width=8,  justify="right")
    sig_table.add_column("Weight",   style="dim white", width=8,  justify="right")
    sig_table.add_column("Weighted", style="white",     width=10, justify="right")
    sig_table.add_column("Bar",      style="cyan",      width=SIGNAL_BAR_WIDTH + 2)
    sig_table.add_column("ATT&CK",   style="dim cyan",  width=12)
    sig_table.add_column("Evidence", style="dim white", min_width=30)

    for s in sorted(candidate.signals, key=lambda x: x.weighted, reverse=True):
        bar = _score_bar(s.score)
        attack_id = s.attack["id"] if s.attack else ""
        row_style = "bold" if s.fired else "dim"
        sig_table.add_row(
            f"[{row_style}]{s.name}[/{row_style}]",
            f"{s.score:.3f}",
            f"{s.weight:.2f}",
            f"{s.weighted:.4f}",
            bar,
            attack_id,
            s.evidence,
        )

    attack_lines = "\n".join(
        f"  [{color}]{t['id']}[/{color}]  {t['name']}"
        for t in candidate.attack_techniques
    ) or "  none"

    time_range = (
        f"{_ts_to_human(candidate.first_seen)} → {_ts_to_human(candidate.last_seen)}"
    )

    panel_content = (
        f"{header}\n"
        f"[dim]time_range:[/dim] {time_range}\n"
        f"[dim]protocols:[/dim] {','.join(candidate.protocols)}\n"
        f"\n[dim bold]ATT&CK Techniques:[/dim bold]\n{attack_lines}\n\n"
    )

    console.print(Panel(panel_content, border_style="dim white", expand=False))
    console.print(sig_table)
    console.print()


def render_json_output(candidates: list[BeaconCandidate]) -> str:
    out = []
    for c in candidates:
        signals_out = []
        for s in c.signals:
            signals_out.append({
                "name":     s.name,
                "score":    s.score,
                "weight":   s.weight,
                "weighted": s.weighted,
                "fired":    s.fired,
                "evidence": s.evidence,
                "attack":   s.attack,
            })
        out.append({
            "destination":        c.destination,
            "total_score":        c.total_score,
            "confidence":         c.confidence,
            "connection_count":   c.connection_count,
            "first_seen":         _ts_to_human(c.first_seen),
            "last_seen":          _ts_to_human(c.last_seen),
            "ports":              sorted(c.ports),
            "protocols":          c.protocols,
            "attack_techniques":  c.attack_techniques,
            "signals":            signals_out,
            "raw_intervals_sample": c.raw_intervals,
        })
    return json.dumps({"beacon_candidates": out}, indent=2)


def _fallback_summary(candidates: list[BeaconCandidate]):
    print(BANNER)
    print(f"\n{'#':<4} {'Destination':<18} {'Score':<8} {'Confidence':<14} {'Sessions':<10} {'ATT&CK'}")
    print("-" * 80)
    for i, c in enumerate(candidates, 1):
        attacks = " ".join(t["id"] for t in c.attack_techniques[:3])
        print(f"{i:<4} {c.destination:<18} {c.total_score:<8.4f} {c.confidence:<14} {c.connection_count:<10} {attacks}")
    print()


def _fallback_detail(candidate: BeaconCandidate):
    print(f"\n--- {candidate.destination} | {candidate.confidence} | score={candidate.total_score:.4f} ---")
    for s in candidate.signals:
        print(f"  {s.name:<25} score={s.score:.3f}  weighted={s.weighted:.4f}  {s.evidence}")
    print()
