# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ChiefGyk3D
# Typo Sniper is dual-licensed; see COMMERCIAL.md for commercial terms.

#!/usr/bin/env python3
"""
Typo Sniper - Advanced Domain Typosquatting Detection Tool

A powerful tool for detecting and monitoring potential typosquatting domains
using dnstwist with enhanced WHOIS data collection, caching, and reporting.

Author: chiefgyk3d
"""

import argparse
import asyncio
import logging
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

# Load environment variables from .env before importing the modules that read
# the environment at import time (Config resolves API keys in its defaults).
load_dotenv()

from ai import AIAnalyzer  # noqa: E402
from cache import Cache  # noqa: E402
from config import Config  # noqa: E402
from exporters import CSVExporter, ExcelExporter, HTMLExporter, JSONExporter  # noqa: E402
from ml import LabelStore  # noqa: E402
from notifiers import dispatch, write_delta_json  # noqa: E402
from scanner import DomainScanner  # noqa: E402
from state import ScanHistory, summarize  # noqa: E402
from utils import parse_interval, setup_logging, validate_domain  # noqa: E402
from version import __version__  # noqa: E402

console = Console()


class TypoSniper:
    """Main application class for Typo Sniper."""

    def __init__(self, config: Config):
        """
        Initialize Typo Sniper.

        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.cache = Cache(config.cache_dir)
        self.scanner = DomainScanner(config, self.cache)
        self.results = []

        self.history = ScanHistory(config.state_dir, config.history_retain)
        self.deltas: list = []
        self.analyzer = AIAnalyzer(config)
        self.ai_results: list = []

        # Loaded once. A missing or stale model is not an error: ranking falls
        # back to the deterministic risk score, which is the default anyway.
        self.triage_model = None
        if config.enable_ml_ranking:
            import ml
            self.triage_model = ml.load(config.state_dir)

    def close(self) -> None:
        """Release the scanner's worker threads."""
        self.scanner.close()

    def load_domains(self, file_path: Path) -> list[str]:
        """
        Load domains from a text file.

        Args:
            file_path: Path to the domain list file

        Returns:
            List of domain names

        Raises:
            FileNotFoundError: If the file doesn't exist
            ValueError: If path validation fails
        """
        # Resolve to absolute path to prevent path traversal
        try:
            resolved_path = file_path.resolve()
        except (OSError, RuntimeError) as e:
            self.logger.error(f"Invalid input file path: {e}")
            raise ValueError(f"Invalid input file path: {e}") from e
        
        # Validate file extension (allow .txt files for domain lists)
        if resolved_path.suffix.lower() not in ['.txt', '']:
            self.logger.error(f"Input file must be a text file (.txt), got: {resolved_path.suffix}")
            raise ValueError(f"Input file must be a text file (.txt), got: {resolved_path.suffix}")
        
        # Check if file exists and is a regular file
        if not resolved_path.exists():
            self.logger.error(f"Domain list file not found: {resolved_path}")
            raise FileNotFoundError(f"Domain list file not found: {resolved_path}")
        
        if not resolved_path.is_file():
            self.logger.error(f"Input path must be a regular file: {resolved_path}")
            raise ValueError(f"Input path must be a regular file: {resolved_path}")
        
        try:
            with open(resolved_path) as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            # Validate domains
            valid_domains = []
            for domain in domains:
                if validate_domain(domain):
                    valid_domains.append(domain)
                else:
                    self.logger.warning(f"Invalid domain format: {domain}")
            
            self.logger.info(f"Loaded {len(valid_domains)} valid domains from {resolved_path}")
            return valid_domains

        except PermissionError:
            self.logger.error(f"Permission denied reading input file: {resolved_path}")
            raise ValueError(f"Permission denied reading input file: {resolved_path}") from None

    async def scan_domains(self, domains: list[str], progress: Progress | None = None) -> None:
        """
        Scan multiple domains for typosquatting variants.

        Args:
            domains: List of domains to scan
            progress: Optional Rich progress bar
        """
        task_id = None
        if progress:
            task_id = progress.add_task("[cyan]Scanning domains...", total=len(domains))

        for domain in domains:
            console.print(f"\n[bold blue]🎯 Scanning: {domain}[/bold blue]")
            
            try:
                result = await self.scanner.scan_domain(domain)
                self._apply_ml_ranking(result)
                self.results.append(result)

                # Diff against the previous scan before recording this one,
                # otherwise the new scan becomes its own baseline.
                if self.config.enable_diff:
                    delta = self.history.diff(result)
                    self.deltas.append(delta)
                    result['delta'] = delta
                    self.history.record(result)
                
                if result['permutations']:
                    console.print(f"[green]✓[/green] Found {len(result['permutations'])} registered permutations")
                    delta = result.get('delta')
                    if delta and not delta.get('first_run'):
                        counts = delta.get('counts', {})
                        notable = counts.get('new', 0) + counts.get('escalated', 0) + counts.get('activated', 0)
                        if notable:
                            console.print(
                                f"[bold yellow]  ↳ {notable} notable change(s) "
                                f"since {delta.get('baseline')}[/bold yellow]"
                            )
                else:
                    console.print("[yellow]○[/yellow] No registered permutations found")
                
            except Exception as e:
                self.logger.error(f"Error scanning {domain}: {e}", exc_info=True)
                console.print(f"[red]✗[/red] Error scanning {domain}: {e}")
            
            if progress and task_id is not None:
                progress.update(task_id, advance=1)

    def export_results(self, output_formats: list[str], output_dir: Path) -> None:
        """
        Export results to specified formats.

        Args:
            output_formats: List of output format names (excel, json, csv, html)
            output_dir: Directory to save output files
            
        Raises:
            ValueError: If output directory path is invalid
        """
        # Resolve to absolute path to prevent path traversal
        try:
            resolved_dir = output_dir.resolve()
        except (OSError, RuntimeError) as e:
            self.logger.error(f"Invalid output directory path: {e}")
            raise ValueError(f"Invalid output directory path: {e}") from e
        
        # Create directory with validated path
        resolved_dir.mkdir(parents=True, exist_ok=True)
        
        # Use resolved path for exports
        output_dir = resolved_dir
        
        exporters = {
            'excel': ExcelExporter(self.config),
            'json': JSONExporter(self.config),
            'csv': CSVExporter(self.config),
            'html': HTMLExporter(self.config),
        }

        for format_name in output_formats:
            if format_name not in exporters:
                self.logger.warning(f"Unknown output format: {format_name}")
                continue
            
            try:
                exporter = exporters[format_name]
                output_file = exporter.export(self.results, output_dir)
                console.print(f"[green]✓[/green] Exported to {output_file}")
            except Exception as e:
                self.logger.error(f"Error exporting to {format_name}: {e}", exc_info=True)
                console.print(f"[red]✗[/red] Error exporting to {format_name}: {e}")

    def _apply_ml_ranking(self, result: dict) -> None:
        """
        Reorder one domain's findings using the trained model.

        Risk scores are left exactly as computed. Only the order changes, plus
        two added fields recording what the model thought and why — so a report
        that was reordered says so, rather than presenting a different order
        with no explanation.

        Args:
            result: Scan result for one monitored domain, modified in place
        """
        if self.triage_model is None:
            return

        monitored = result.get('original_domain', '')
        permutations = result.get('permutations') or []

        for perm in permutations:
            try:
                perm['ml_rank'] = round(
                    self.triage_model.score(perm, monitored), 4
                )
                perm['ml_explain'] = [
                    {'feature': name, 'contribution': round(value, 3)}
                    for name, value in self.triage_model.explain(
                        perm, monitored, self.config.ml_explain_top
                    )
                ]
            except Exception as e:
                # A scoring failure must not cost the finding. The scan's own
                # output is complete without it.
                self.logger.warning(
                    f'Could not rank {perm.get("domain")}: {type(e).__name__}'
                )
                perm['ml_rank'] = None

        # Unranked findings sort last rather than to the top with a 0
        permutations.sort(
            key=lambda p: (p.get('ml_rank') is not None, p.get('ml_rank') or 0.0),
            reverse=True,
        )

    def print_summary(self) -> None:
        """Print a summary of scan results."""
        from rich.table import Table

        table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
        table.add_column("Domain", style="cyan", width=28)
        table.add_column("Registered", justify="right", style="green")
        table.add_column("Recent", justify="right", style="yellow")
        table.add_column("High Risk", justify="right", style="red")
        table.add_column("WHOIS", justify="right", style="blue")

        total_perms = 0
        total_recent = 0
        total_high_risk = 0
        total_whois_failed = 0

        for result in self.results:
            perms = result['permutations']
            recent = len([p for p in perms if p.get('is_recent', False)])
            high_risk = len([p for p in perms if (p.get('risk_score') or 0) >= 70])
            whois_ok = result.get('whois_succeeded', 0)
            whois_failed = result.get('whois_failed', 0)

            total_perms += len(perms)
            total_recent += recent
            total_high_risk += high_risk
            total_whois_failed += whois_failed

            table.add_row(
                result['original_domain'],
                str(len(perms)),
                str(recent) if recent else "-",
                str(high_risk) if high_risk else "-",
                f"{whois_ok}/{whois_ok + whois_failed}",
            )

        console.print("\n")
        console.print(table)
        console.print(f"\n[bold]Total Registered Permutations:[/bold] {total_perms}")
        console.print(
            f"[bold]Recently Registered (<= {self.config.recent_days} days):[/bold] {total_recent}"
        )
        console.print(f"[bold]High Risk (score >= 70):[/bold] {total_high_risk}")

        # A wholly failed WHOIS stage previously looked identical to a clean
        # scan with no recent registrations. Say so explicitly.
        if total_whois_failed:
            console.print(
                f"[yellow]⚠ WHOIS data unavailable for {total_whois_failed} domain(s). "
                f"Registration dates and recency scoring are incomplete.[/yellow]"
            )


    def print_changes(self) -> dict:
        """
        Print what changed since the previous scan.

        Returns:
            The aggregate delta summary
        """
        from rich.table import Table

        summary = summarize(self.deltas)

        if summary.get('first_runs'):
            console.print(
                f"\n[dim]Baseline established for "
                f"{len(summary['first_runs'])} domain(s); "
                f"changes will be reported from the next scan.[/dim]"
            )

        if not summary['changes']:
            if not summary.get('first_runs'):
                console.print("\n[green]No changes since the previous scan.[/green]")
            return summary

        table = Table(
            title="Changes Since Last Scan",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Change", width=10)
        table.add_column("Domain", style="cyan", width=32)
        table.add_column("Risk", justify="right", width=5)
        table.add_column("Detail")

        styles = {
            'new': 'bold red',
            'escalated': 'bold yellow',
            'activated': 'yellow',
            'changed': 'blue',
            'resolved': 'green',
        }

        for change in summary['changes'][:40]:
            style = styles.get(change['kind'], '')
            score = change.get('risk_score')
            table.add_row(
                f"[{style}]{change['kind'].upper()}[/{style}]" if style else change['kind'],
                change['domain'],
                str(score) if isinstance(score, (int, float)) else '-',
                str(change.get('detail', '')),
            )

        console.print("\n")
        console.print(table)

        if summary['total_changes'] > 40:
            console.print(f"[dim]…and {summary['total_changes'] - 40} more.[/dim]")

        return summary

    async def run_ai_analysis(self, summary: dict | None) -> None:
        """
        Run AI triage over the findings and, when configured, the delta.

        Strictly additive: any failure is reported and the deterministic
        results are untouched.

        Args:
            summary: Aggregate delta summary, or None when diffing is off
        """
        ready, reason = self.analyzer.status()
        if not ready:
            if self.config.enable_ai_analysis:
                console.print(f"[yellow]⚠ AI triage skipped: {reason}[/yellow]")
            return

        console.print("\n[bold]Running AI triage…[/bold]")

        for result in self.results:
            outcome = await self.analyzer.triage(
                result['original_domain'], result.get('permutations', [])
            )
            if outcome is None:
                continue
            if not outcome.ok:
                console.print(f"[red]✗[/red] AI triage failed: {outcome.error}")
                continue

            result['ai_analysis'] = outcome.content
            self.ai_results.append(outcome)
            self._print_ai_result(result['original_domain'], outcome)

        if summary and self.config.ai_explain_changes:
            outcome = await self.analyzer.explain_changes(summary)
            if outcome and outcome.ok:
                summary['ai_analysis'] = outcome.content
                self.ai_results.append(outcome)
                text = outcome.content.get('summary')
                if text:
                    console.print(f"\n[bold]AI summary of changes:[/bold] {text}")

        usage = self.analyzer.usage_summary()
        if usage['input_tokens'] or usage['output_tokens']:
            console.print(
                f"[dim]AI tokens: {usage['input_tokens']} in, "
                f"{usage['output_tokens']} out ({usage['provider']})[/dim]"
            )

        if usage['injection_attempts']:
            # Not a nuisance to suppress: a WHOIS record containing text aimed
            # at the analysis system is evidence about who registered it.
            console.print(
                f"[bold red]⚠ {len(usage['injection_attempts'])} domain(s) carried "
                f"text targeting the analysis system — treat as a signal of "
                f"deliberate evasion:[/bold red] "
                f"{', '.join(usage['injection_attempts'][:5])}"
            )

    def _print_ai_result(self, domain: str, outcome) -> None:
        """Render one AI assessment to the console."""
        from rich.table import Table

        content = outcome.content
        if content.get('summary'):
            console.print(f"\n[bold cyan]{domain}[/bold cyan]: {content['summary']}")

        assessments = content.get('assessments') or []
        if not assessments:
            return

        table = Table(show_header=True, header_style="bold magenta", box=None)
        table.add_column("Domain", style="cyan", width=30)
        table.add_column("Action", width=12)
        table.add_column("Conf.", width=7)
        table.add_column("Reading")

        colours = {'escalate': 'bold red', 'investigate': 'yellow',
                   'monitor': 'blue', 'no action': 'green'}

        for a in assessments[:15]:
            action = str(a.get('suggested_action', ''))
            style = colours.get(action, '')
            table.add_row(
                str(a.get('domain', '')),
                f"[{style}]{action}[/{style}]" if style else action,
                str(a.get('confidence', '')),
                str(a.get('reading', ''))[:160],
            )

        console.print(table)
        console.print("[dim]AI assessments are advisory. Risk scores above are "
                      "computed deterministically and are not model output.[/dim]")

    async def notify(self, summary: dict) -> None:
        """
        Deliver the delta summary through configured alert channels.

        Args:
            summary: Aggregate delta summary
        """
        if not self.config.enable_notifications:
            return

        import aiohttp

        try:
            timeout = aiohttp.ClientTimeout(total=self.config.notify_timeout + 10)
            async with aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': self.config.user_agent},
            ) as session:
                results = await dispatch(summary, self.config, session)

            for channel, ok in results.items():
                if ok:
                    console.print(f"[green]✓[/green] Alert sent via {channel}")
                else:
                    console.print(f"[red]✗[/red] Alert failed via {channel}")
        except Exception as e:
            self.logger.error(f"Notification dispatch failed: {e}", exc_info=True)
            console.print(f"[red]✗[/red] Notification dispatch failed: {e}")

    def reset(self) -> None:
        """Clear per-scan results so the instance can run again in watch mode."""
        self.results = []
        self.deltas = []
        self.ai_results = []


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Typo Sniper - Advanced Domain Typosquatting Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan domains from file with default settings
  python typo_sniper.py -i domains.txt

  # Monitor continuously and alert Slack when something changes
  python typo_sniper.py -i domains.txt --watch --interval 6h --notify slack

  # Filter domains registered in the last 3 months
  python typo_sniper.py -i domains.txt --months 3

  # Export to multiple formats
  python typo_sniper.py -i domains.txt -o results/ --format excel json html

  # Use custom configuration
  python typo_sniper.py -i domains.txt --config config.yaml

  # Verbose output with debug logging
  python typo_sniper.py -i domains.txt -v
        """
    )

    parser.add_argument(
        '-i', '--input',
        type=Path,
        default=Path('monitored_domains.txt'),
        help='Input file containing domains to monitor (default: monitored_domains.txt)'
    )

    parser.add_argument(
        '-o', '--output',
        type=Path,
        default=Path('results'),
        help='Output directory for results (default: results/)'
    )

    parser.add_argument(
        '--format',
        nargs='+',
        choices=['excel', 'json', 'csv', 'html'],
        default=['excel'],
        help='Output formats (default: excel)'
    )

    parser.add_argument(
        '--months',
        type=int,
        default=0,
        help='Filter domains registered within the last N months (0 = no filter)'
    )

    parser.add_argument(
        '--config',
        type=Path,
        help='Path to configuration file (YAML format)'
    )

    parser.add_argument(
        '--max-workers',
        type=int,
        default=10,
        help='Maximum number of concurrent workers (default: 10)'
    )

    parser.add_argument(
        '--cache-ttl',
        type=int,
        default=86400,
        help='Cache TTL in seconds (default: 86400 = 24 hours)'
    )

    parser.add_argument(
        '--no-cache',
        action='store_true',
        help='Disable caching'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output (INFO level)'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output (DEBUG level with enhanced tracing)'
    )

    parser.add_argument(
        '--watch',
        action='store_true',
        help='Run continuously, rescanning on an interval (see --interval)'
    )

    parser.add_argument(
        '--interval',
        type=str,
        default=None,
        help='Interval between scans in watch mode, e.g. 6h, 30m, 86400 (default: 24h)'
    )

    parser.add_argument(
        '--no-diff',
        action='store_true',
        help='Disable change detection against previous scans'
    )

    parser.add_argument(
        '--notify',
        nargs='+',
        choices=['slack', 'discord', 'teams', 'matrix', 'jira', 'webhook', 'email'],
        default=None,
        help='Alert channels to notify when changes are detected. '
             "'jira' opens one deduplicated ticket per domain rather than "
             'sending a message.'
    )

    parser.add_argument(
        '--notify-min-changes',
        type=int,
        default=None,
        help='Only alert when at least this many changes are detected (default: 1)'
    )

    parser.add_argument(
        '--no-rdap',
        action='store_true',
        help='Skip RDAP and use WHOIS only for registration data'
    )

    parser.add_argument(
        '--label',
        action='append',
        metavar='DOMAIN=acted|dismissed',
        default=None,
        help='Record a judgement about a finding, then exit. Repeatable. '
             "'acted' means worth acting on, 'dismissed' means reviewed and "
             'not worth acting on; both are needed to train.'
    )

    parser.add_argument(
        '--ml-train',
        action='store_true',
        help='Train the triage ranking model on labelled history, then exit'
    )

    parser.add_argument(
        '--ml-status',
        action='store_true',
        help='Report label counts and the trained model, then exit'
    )

    parser.add_argument(
        '--ml-rank',
        action='store_true',
        help='Order findings by the trained model. Risk scores are unchanged.'
    )

    parser.add_argument(
        '--secrets-check',
        action='store_true',
        help='Report which secrets backends are reachable and where each '
             'credential resolved from, then exit. Never prints a value.'
    )

    parser.add_argument(
        '--ai',
        action='store_true',
        help='Enable AI-assisted triage of findings (explains, never scores)'
    )

    parser.add_argument(
        '--ai-provider',
        choices=['claude', 'openai', 'gemini', 'ollama'],
        default=None,
        help='AI backend to use (default: claude; ollama keeps data on your host)'
    )

    parser.add_argument(
        '--ai-model',
        type=str,
        default=None,
        help="Model name for the chosen provider (default: the provider's own)"
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'Typo Sniper v{__version__}'
    )

    return parser.parse_args()


def apply_labels(config, specs: list[str]) -> int:
    """
    Record operator judgements about findings.

    Args:
        config: Configuration object
        specs: Strings of the form ``domain=acted`` or ``domain=dismissed``

    Returns:
        Process exit code
    """
    from ml.labels import VALID_LABELS

    store = LabelStore(config.state_dir)
    failures = 0

    for spec in specs:
        domain, _, label = spec.partition('=')
        domain, label = domain.strip(), label.strip().lower()

        if not label:
            console.print(
                f"[red]✗[/red] '{spec}': expected DOMAIN=acted or DOMAIN=dismissed"
            )
            failures += 1
            continue

        try:
            store.set(domain, label)
        except ValueError as e:
            console.print(f'[red]✗[/red] {e}')
            failures += 1
            continue

        console.print(f'[green]✓[/green] {domain} labelled [bold]{label}[/bold]')

    ready, reason = store.readiness()
    marker = '[green]✓[/green]' if ready else '[yellow]•[/yellow]'
    console.print(f'\n{marker} {reason}')
    if not ready:
        console.print(
            f'[dim]Valid labels: {", ".join(VALID_LABELS)}. Both are needed — a '
            f'model cannot learn a boundary from one side of it.[/dim]'
        )
    return 1 if failures else 0


def print_ml_status(config, domains: list[str] | None = None) -> None:
    """
    Report what the learned-triage layer currently has to work with.

    Args:
        config: Configuration object
        domains: Monitored domains whose history should be counted
    """
    import ml
    from ml.model import model_path

    store = LabelStore(config.state_dir)
    counts = store.counts()
    ready, reason = store.readiness()

    console.print('\n[bold]Labels[/bold]')
    console.print(f"  acted:     {counts.get('acted', 0)}")
    console.print(f"  dismissed: {counts.get('dismissed', 0)}")
    marker = '[green]✓[/green]' if ready else '[yellow]•[/yellow]'
    console.print(f'  {marker} {reason}')

    console.print('\n[bold]Model[/bold]')
    model = ml.load(config.state_dir)
    if model is None:
        exists = model_path(config.state_dir).exists()
        console.print(
            '  [yellow]none trained[/yellow]'
            if not exists else
            '  [yellow]present but unusable — retrain with --ml-train[/yellow]'
        )
    else:
        meta = model.metadata
        auc = meta.get('cv_roc_auc')
        console.print(f"  trained on {meta.get('samples', 0)} labels "
                      f"({meta.get('acted', 0)} acted, {meta.get('dismissed', 0)} dismissed)")
        if isinstance(auc, (int, float)) and auc == auc:  # not NaN
            console.print(f"  cross-validated ROC AUC: {auc:.3f} "
                          f"(±{meta.get('cv_roc_auc_std', 0):.3f}, "
                          f"{meta.get('cv_folds', 0)} folds)")
        console.print('  [bold]most influential features[/bold]')
        for name, weight in model.influential_features(6):
            console.print(f'    {name:<26} {weight:+.3f}')

    if domains:
        history = ScanHistory(config.state_dir, config.history_retain)
        dataset = ml.build(history, store, domains)
        console.print(f'\n[bold]Training set[/bold]\n  {len(dataset)} labelled '
                      f'domain(s) matched to scan history')
        if dataset.unmatched:
            console.print(f'  [yellow]{len(dataset.unmatched)} labelled domain(s) '
                          f'have no retained history and cannot be used[/yellow]')

    console.print(
        '\n[dim]The model ranks findings; it does not score them. Risk scores '
        'stay deterministic so a takedown request can cite them.[/dim]\n'
    )


def run_ml_training(config, domains: list[str]) -> int:
    """
    Train the ranking model on labelled history.

    Args:
        config: Configuration object
        domains: Monitored domains whose history holds the labelled findings

    Returns:
        Process exit code
    """
    import ml

    if not ml.sklearn_available():
        console.print(
            '[red]✗[/red] Training needs scikit-learn, which is not installed.\n'
            '  [dim]pip install -e ".[ml]"[/dim]\n'
            '  [dim]Only training needs it. Scoring is pure Python, so hosts '
            'that run scans do not.[/dim]'
        )
        return 1

    store = LabelStore(config.state_dir)
    ready, reason = store.readiness()
    if not ready:
        console.print(f'[yellow]•[/yellow] Not enough labelled data yet: {reason}')
        return 1

    history = ScanHistory(config.state_dir, config.history_retain)
    dataset = ml.build(history, store, domains)

    if len(dataset) < config.ml_min_labels:
        console.print(
            f'[yellow]•[/yellow] Only {len(dataset)} labelled domain(s) matched '
            f'scan history, below the {config.ml_min_labels} required.'
        )
        if dataset.unmatched:
            console.print(
                f'  [dim]{len(dataset.unmatched)} label(s) refer to domains with '
                f'no retained history.[/dim]'
            )
        return 1

    counts = dataset.class_counts
    if not counts['acted'] or not counts['dismissed']:
        console.print(
            '[yellow]•[/yellow] The matched labels are all one class. A model '
            'needs examples of both to learn where the boundary is.'
        )
        return 1

    console.print(f'\n[bold]Training on {len(dataset)} labelled findings[/bold] '
                  f"({counts['acted']} acted, {counts['dismissed']} dismissed)")

    report = ml.train(dataset, config.state_dir)

    auc = report['cv_roc_auc']
    console.print(f"[green]✓[/green] Model written to {report['path']}")
    if auc == auc:  # not NaN
        console.print(f"  cross-validated ROC AUC: {auc:.3f} "
                      f"(±{report['cv_roc_auc_std']:.3f} over {report['cv_folds']} folds)")
        if auc < 0.65:
            console.print(
                '  [yellow]That is close to guessing. More labels, or labels '
                'that disagree with the risk score more often, would help.[/yellow]'
            )
    console.print('\n  [bold]most influential features[/bold]')
    for name, weight in report['influential_features'][:8]:
        console.print(f'    {name:<26} {weight:+.3f}')
    console.print(
        '\n[dim]Run a scan with --ml-rank to order findings by this model. '
        'Risk scores are unaffected.[/dim]\n'
    )
    return 0


def print_secrets_check(config) -> None:
    """
    Report secret resolution without disclosing any secret.

    Operators debugging a missing API key otherwise reach for echo, which puts
    the value in their shell history. This prints only whether each credential
    was found and which backend supplied it.

    Args:
        config: Configuration object, already resolved
    """
    from rich.table import Table

    from secrets_manager import BACKENDS

    backends = Table(title='Secrets backends', title_justify='left')
    backends.add_column('Backend')
    backends.add_column('Status')
    for entry in config.secrets.describe():
        colour = {'ready': 'green', 'not configured': 'dim'}.get(entry['status'], 'red')
        backends.add_row(entry['backend'], f"[{colour}]{entry['status']}[/{colour}]")
    console.print(backends)

    if config.secrets.unknown_backends:
        # The offending value is deliberately not echoed here or in the log
        console.print(
            f"[yellow]{config.secrets.unknown_backends} entry in "
            f"secrets_backends was not recognised and is being ignored. "
            f"Valid names: {', '.join(BACKENDS)}.[/yellow]"
        )

    credentials = Table(title='Credentials', title_justify='left')
    credentials.add_column('Name')
    credentials.add_column('Resolved')
    credentials.add_column('Source')
    for attr, _aliases in config.SECRET_FIELDS:
        value = getattr(config, attr, None)
        # A value present without a recorded lookup came from the config file
        source = config.secrets.resolved_from.get(attr, 'config file' if value else '—')
        credentials.add_row(
            attr,
            '[green]yes[/green]' if value else '[dim]no[/dim]',
            source,
        )
    console.print(credentials)
    console.print(
        '\n[dim]Values are never printed. Set TYPO_SNIPER_<NAME> to override '
        'any single credential for one run.[/dim]\n'
    )


async def run_scan(sniper, domains, args, config) -> None:
    """
    Run one full scan cycle: scan, diff, report, export, alert.

    Args:
        sniper: TypoSniper instance
        domains: Domains to scan
        args: Parsed CLI arguments
        config: Configuration object
    """
    sniper.reset()

    console.print()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        await sniper.scan_domains(domains, progress)

    sniper.print_summary()

    summary = None
    if config.enable_diff:
        summary = sniper.print_changes()

    console.print("\n[bold]Exporting results...[/bold]")
    sniper.export_results(args.format, args.output)

    await sniper.run_ai_analysis(summary)

    if summary is not None:
        try:
            output_dir = Path(args.output).resolve()
            output_dir.mkdir(parents=True, exist_ok=True)
            delta_path = output_dir / 'latest_changes.json'
            write_delta_json(summary, delta_path)
            console.print(f"[green]✓[/green] Change summary written to {delta_path}")
        except OSError as e:
            sniper.logger.warning(f"Could not write change summary: {e}")

        await sniper.notify(summary)


async def main():
    """Main entry point."""
    args = parse_arguments()

    # Setup logging
    if args.debug:
        log_level = logging.DEBUG
        debug_mode = True
    elif args.verbose:
        log_level = logging.INFO
        debug_mode = False
    else:
        log_level = logging.WARNING
        debug_mode = False

    setup_logging(log_level)
    logger = logging.getLogger(__name__)

    # Load configuration
    config = Config.from_file(args.config) if args.config else Config()

    if args.secrets_check:
        print_secrets_check(config)
        return

    if args.ml_rank:
        config.enable_ml_ranking = True

    if args.label:
        code = apply_labels(config, args.label)
        if code:
            sys.exit(code)
        return

    # Override config with command-line arguments
    config.max_workers = args.max_workers
    config.cache_ttl = args.cache_ttl
    config.use_cache = not args.no_cache
    config.months_filter = args.months
    config.debug_mode = debug_mode

    if args.no_diff:
        config.enable_diff = False
    if args.no_rdap:
        config.use_rdap = False
    if args.notify:
        config.notify_channels = list(args.notify)
        config.enable_notifications = True
    if args.notify_min_changes is not None:
        config.notify_min_changes = args.notify_min_changes
    if args.interval:
        config.watch_interval = parse_interval(args.interval, config.watch_interval)
    if args.ai:
        config.enable_ai_analysis = True
    if args.ai_provider:
        config.ai_provider = args.ai_provider
        config.enable_ai_analysis = True
    if args.ai_model:
        config.ai_model = args.ai_model

    # Display banner
    console.print("\n[bold cyan]" + "=" * 60 + "[/bold cyan]")
    console.print(
        f"[bold cyan]      🎯 Typo Sniper v{__version__} - Typosquatting Detector[/bold cyan]"
    )
    console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]\n")

    sniper = TypoSniper(config)

    exit_code = 0
    try:
        domains = sniper.load_domains(args.input)

        if not domains:
            console.print("[red]No valid domains found in input file![/red]")
            sniper.close()
            sys.exit(1)

        if args.ml_status:
            print_ml_status(config, domains)
            sniper.close()
            return

        if args.ml_train:
            code = run_ml_training(config, domains)
            sniper.close()
            if code:
                sys.exit(code)
            return

        console.print(f"[bold]Domains to scan:[/bold] {len(domains)}")
        console.print(f"[bold]Output formats:[/bold] {', '.join(args.format)}")
        console.print(f"[bold]Cache enabled:[/bold] {'Yes' if config.use_cache else 'No'}")
        console.print(
            f"[bold]Registration lookup:[/bold] "
            f"{'RDAP (WHOIS fallback)' if config.use_rdap else 'WHOIS only'}"
        )
        console.print(
            f"[bold]Change detection:[/bold] {'On' if config.enable_diff else 'Off'}"
        )
        if config.enable_notifications:
            console.print(
                f"[bold]Alerts:[/bold] {', '.join(config.notify_channels) or 'none configured'}"
            )
        if config.enable_ai_analysis:
            ready, reason = sniper.analyzer.status()
            console.print(
                "[bold]AI triage:[/bold] "
                + (config.ai_provider if ready else f"[yellow]unavailable ({reason})[/yellow]")
            )
        if config.enable_ml_ranking:
            console.print(
                '[bold]Ranking:[/bold] '
                + ('learned triage model' if sniper.triage_model
                   else '[yellow]no usable model; using risk score[/yellow]')
            )
        if args.months > 0:
            console.print(
                f"[bold]Filter:[/bold] Domains registered in last {args.months} months"
            )

        if args.watch:
            interval = config.watch_interval
            console.print(
                f"[bold]Watch mode:[/bold] rescanning every "
                f"{interval}s ({interval // 3600}h {(interval % 3600) // 60}m). "
                f"Press Ctrl+C to stop.\n"
            )

            cycle = 0
            while True:
                cycle += 1
                console.print(
                    f"[bold cyan]── Scan #{cycle} — "
                    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ──[/bold cyan]"
                )
                await run_scan(sniper, domains, args, config)
                console.print(
                    f"\n[dim]Sleeping {interval}s until the next scan…[/dim]\n"
                )
                await asyncio.sleep(interval)
        else:
            await run_scan(sniper, domains, args, config)
            console.print("\n[bold green]✓ Scan completed successfully![/bold green]\n")

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        exit_code = 130
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        console.print(f"\n[bold red]✗ Fatal error: {e}[/bold red]\n")
        exit_code = 1
    finally:
        sniper.close()

    if exit_code:
        sys.exit(exit_code)


if __name__ == '__main__':
    asyncio.run(main())
