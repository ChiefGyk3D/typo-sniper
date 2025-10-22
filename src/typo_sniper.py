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
from datetime import date, timedelta
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

# Load environment variables from .env file
load_dotenv()

from scanner import DomainScanner
from exporters import ExcelExporter, JSONExporter, CSVExporter, HTMLExporter
from config import Config
from cache import Cache
from utils import setup_logging, validate_domain


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

    def load_domains(self, file_path: Path) -> List[str]:
        """
        Load domains from a text file.

        Args:
            file_path: Path to the domain list file

        Returns:
            List of domain names

        Raises:
            FileNotFoundError: If the file doesn't exist
        """
        try:
            with open(file_path, 'r') as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            # Validate domains
            valid_domains = []
            for domain in domains:
                if validate_domain(domain):
                    valid_domains.append(domain)
                else:
                    self.logger.warning(f"Invalid domain format: {domain}")
            
            self.logger.info(f"Loaded {len(valid_domains)} valid domains from {file_path}")
            return valid_domains

        except FileNotFoundError:
            self.logger.error(f"Domain list file not found: {file_path}")
            raise

    async def scan_domains(self, domains: List[str], progress: Optional[Progress] = None) -> None:
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
                
                if result['permutations']:
                    console.print(f"[green]✓[/green] Found {len(result['permutations'])} registered permutations")
                else:
                    console.print(f"[yellow]○[/yellow] No registered permutations found")
                
            except Exception as e:
                self.logger.error(f"Error scanning {domain}: {e}", exc_info=True)
                console.print(f"[red]✗[/red] Error scanning {domain}: {e}")
            
            if progress and task_id is not None:
                progress.update(task_id, advance=1)

    def export_results(self, output_formats: List[str], output_dir: Path) -> None:
        """
        Export results to specified formats.

        Args:
            output_formats: List of output format names (excel, json, csv, html)
            output_dir: Directory to save output files
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        
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
        table.add_column("Domain", style="cyan", width=30)
        table.add_column("Permutations Found", justify="right", style="green")
        table.add_column("Recent Registrations", justify="right", style="yellow")

        total_perms = 0
        total_recent = 0

        for result in self.results:
            perms = len(result['permutations'])
            recent = len([p for p in result['permutations'] if p.get('is_recent', False)])
            total_perms += perms
            total_recent += recent
            
            table.add_row(
                result['original_domain'],
                str(perms),
                str(recent) if recent > 0 else "-"
            )

        console.print("\n")
        console.print(table)
        console.print(f"\n[bold]Total Permutations:[/bold] {total_perms}")
        console.print(f"[bold]Recent Registrations:[/bold] {total_recent}")


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Typo Sniper - Advanced Domain Typosquatting Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan domains from file with default settings
  python typo_sniper.py -i domains.txt

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
        '--version',
        action='version',
        version='Typo Sniper v1.0.0'
    )

    return parser.parse_args()


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
    
    # Store debug mode in config for access by other modules
    config.debug_mode = debug_mode

    # Display banner
    console.print("\n[bold cyan]" + "=" * 60 + "[/bold cyan]")
    console.print("[bold cyan]         🎯 Typo Sniper 1.0 - Typosquatting Detector[/bold cyan]")
    console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]\n")

    # Initialize Typo Sniper
    sniper = TypoSniper(config)

    try:
        # Load domains
        domains = sniper.load_domains(args.input)
        
        if not domains:
            console.print("[red]No valid domains found in input file![/red]")
            sys.exit(1)

        console.print(f"[bold]Domains to scan:[/bold] {len(domains)}")
        console.print(f"[bold]Output formats:[/bold] {', '.join(args.format)}")
        console.print(f"[bold]Cache enabled:[/bold] {'Yes' if config.use_cache else 'No'}")
        
        if args.months > 0:
            console.print(f"[bold]Filter:[/bold] Domains registered in last {args.months} months")

        # Scan domains with progress bar
        console.print()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            await sniper.scan_domains(domains, progress)

        # Print summary
        sniper.print_summary()

        # Export results
        console.print(f"\n[bold]Exporting results...[/bold]")
        sniper.export_results(args.format, args.output)

        console.print("\n[bold green]✓ Scan completed successfully![/bold green]\n")

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        console.print(f"\n[bold red]✗ Fatal error: {e}[/bold red]\n")
        sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())
