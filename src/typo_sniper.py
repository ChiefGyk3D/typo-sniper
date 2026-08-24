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

from cache import Cache  # noqa: E402
from config import Config  # noqa: E402
from exporters import CSVExporter, ExcelExporter, HTMLExporter, JSONExporter  # noqa: E402
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
        choices=['slack', 'discord', 'webhook', 'email'],
        default=None,
        help='Alert channels to notify when changes are detected'
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
        '--version',
        action='version',
        version=f'Typo Sniper v{__version__}'
    )

    return parser.parse_args()


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
