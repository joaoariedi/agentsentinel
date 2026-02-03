#!/usr/bin/env python3
"""
AgentSentinel Red Team - Command Line Interface

CLI tool for running security scans against AI agents.
"""

import argparse
import asyncio
import json
import sys
from typing import List, Optional

from .payloads import (
    PAYLOAD_LIBRARY,
    PayloadCategory,
    Severity,
    get_payload_count_by_category,
    get_payload_count_by_severity,
)
from .reporter import ReportGenerator, save_report
from .scanner import AgentScanner, ScanResult


def parse_headers(header_args: Optional[List[str]]) -> dict:
    """Parse header arguments into a dictionary."""
    headers = {}
    if header_args:
        for h in header_args:
            if ":" in h:
                key, value = h.split(":", 1)
                headers[key.strip()] = value.strip()
    return headers


def print_banner():
    """Print the AgentSentinel banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                 AgentSentinel Red Team Suite                  ║
║               Security Testing for AI Agents                  ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_payload_stats():
    """Print statistics about available payloads."""
    print("📊 Payload Library Statistics:")
    print(f"   Total payloads: {len(PAYLOAD_LIBRARY)}")
    print()
    
    print("   By Category:")
    for category, count in get_payload_count_by_category().items():
        print(f"     • {category.replace('_', ' ').title()}: {count}")
    print()
    
    print("   By Severity:")
    for severity, count in get_payload_count_by_severity().items():
        print(f"     • {severity.upper()}: {count}")
    print()


async def run_scan(args) -> int:
    """Run the security scan based on CLI arguments."""
    # Parse options
    headers = parse_headers(args.header)
    categories = [PayloadCategory(args.category)] if args.category else None
    severities = [Severity(args.severity)] if args.severity else None
    
    # Initialize scanner
    scanner = AgentScanner(
        request_delay_ms=args.delay,
        timeout_seconds=args.timeout,
        max_concurrent=args.concurrent,
    )
    
    # Progress display
    last_line_length = 0
    
    async def progress_callback(done: int, total: int, result: Optional[ScanResult]):
        nonlocal last_line_length
        
        if result and result.success:
            status = "🔴 VULN"
        elif result and result.error:
            status = "⚠️ ERR"
        else:
            status = "🟢 OK"
        
        bar_width = 30
        filled = int(bar_width * done / total)
        bar = "█" * filled + "░" * (bar_width - filled)
        
        line = f"\r[{bar}] {done}/{total} ({done/total*100:.0f}%) {status}"
        
        # Clear previous line if needed
        if len(line) < last_line_length:
            line += " " * (last_line_length - len(line))
        last_line_length = len(line)
        
        print(line, end="", flush=True)
    
    scanner.set_progress_callback(progress_callback)
    
    # Print scan info
    print(f"🎯 Target: {args.target}")
    if categories:
        print(f"📂 Category: {args.category}")
    if severities:
        print(f"⚡ Severity: {args.severity}")
    if args.quick:
        print("🚀 Mode: Quick scan (critical payloads only)")
    print()
    print("🔍 Starting security scan...")
    print()
    
    # Run scan
    try:
        if args.quick:
            report = await scanner.quick_scan(args.target, headers=headers)
        else:
            report = await scanner.scan(
                args.target,
                headers=headers,
                categories=categories,
                severities=severities,
            )
    except KeyboardInterrupt:
        print("\n\n⚠️ Scan cancelled by user")
        return 1
    except Exception as e:
        print(f"\n\n❌ Scan failed: {e}")
        return 1
    
    # Clear progress line
    print("\n")
    
    # Generate report
    generator = ReportGenerator()
    
    # Print summary
    print("=" * 60)
    print(generator.generate_summary(report))
    print("=" * 60)
    print()
    
    # Show critical vulnerabilities
    critical = report.get_critical_vulnerabilities()
    if critical:
        print("🚨 CRITICAL VULNERABILITIES FOUND:")
        for v in critical:
            print(f"   • {v.payload.name} ({v.payload.id})")
        print()
    
    # Save report if requested
    if args.output:
        try:
            if args.format == "json":
                content = json.dumps(generator.generate_json(report), indent=2)
            else:
                content = generator.generate_markdown(report)
            
            with open(args.output, "w") as f:
                f.write(content)
            
            print(f"📄 Report saved to: {args.output}")
        except Exception as e:
            print(f"❌ Failed to save report: {e}")
            return 1
    
    # Print full report to stdout if no output file and verbose
    if args.verbose and not args.output:
        print()
        print(generator.generate_markdown(report, detailed=True))
    
    # Return exit code based on vulnerabilities
    if report.vulnerabilities_found > 0:
        return 2  # Vulnerabilities found
    return 0  # Success, no vulnerabilities


def cmd_scan(args):
    """Handle the scan command."""
    print_banner()
    return asyncio.run(run_scan(args))


def cmd_list(args):
    """Handle the list command."""
    print_banner()
    print_payload_stats()
    
    if args.verbose:
        print("📋 Available Payloads:")
        print()
        
        for category in PayloadCategory:
            payloads = [p for p in PAYLOAD_LIBRARY if p.category == category]
            if payloads:
                print(f"  {category.value.replace('_', ' ').title()}:")
                for p in payloads:
                    severity_emoji = {
                        Severity.LOW: "🟢",
                        Severity.MEDIUM: "🟡",
                        Severity.HIGH: "🟠",
                        Severity.CRITICAL: "🔴",
                    }[p.severity]
                    print(f"    {severity_emoji} {p.id}: {p.name}")
                print()
    
    return 0


def cmd_info(args):
    """Handle the info command for a specific payload."""
    print_banner()
    
    payload = None
    for p in PAYLOAD_LIBRARY:
        if p.id == args.payload_id:
            payload = p
            break
    
    if not payload:
        print(f"❌ Payload not found: {args.payload_id}")
        return 1
    
    print(f"📋 Payload Details: {payload.id}")
    print()
    print(f"  Name: {payload.name}")
    print(f"  Category: {payload.category.value.replace('_', ' ').title()}")
    print(f"  Severity: {payload.severity.value.upper()}")
    print(f"  Description: {payload.description}")
    print(f"  Tags: {', '.join(payload.tags)}")
    print()
    print("  Payload:")
    print("  " + "-" * 50)
    for line in payload.payload.split("\n"):
        print(f"  {line}")
    print("  " + "-" * 50)
    print()
    print("  Success Indicators:")
    for ind in payload.success_indicators:
        print(f"    • {ind}")
    print()
    
    return 0


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="agentsentinel-redteam",
        description="AgentSentinel Red Team Suite - Security testing for AI agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick scan (critical payloads only)
  agentsentinel-redteam scan https://api.example.com/chat --quick
  
  # Full scan with markdown report
  agentsentinel-redteam scan https://api.example.com/chat -o report.md
  
  # Scan specific category
  agentsentinel-redteam scan https://api.example.com/chat --category prompt_extraction
  
  # Scan with custom headers
  agentsentinel-redteam scan https://api.example.com/chat -H "Authorization: Bearer token"
  
  # List all available payloads
  agentsentinel-redteam list -v
  
  # Get info about a specific payload
  agentsentinel-redteam info io-001
""",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run security scan against a target")
    scan_parser.add_argument("target", help="Target agent URL")
    scan_parser.add_argument(
        "--quick", "-q",
        action="store_true",
        help="Quick scan (critical severity only)",
    )
    scan_parser.add_argument(
        "--category", "-c",
        choices=[c.value for c in PayloadCategory],
        help="Filter by payload category",
    )
    scan_parser.add_argument(
        "--severity", "-s",
        choices=[s.value for s in Severity],
        help="Filter by severity level",
    )
    scan_parser.add_argument(
        "--output", "-o",
        help="Output file path",
    )
    scan_parser.add_argument(
        "--format", "-f",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    scan_parser.add_argument(
        "--header", "-H",
        action="append",
        help="Add HTTP header (format: 'Key: Value')",
    )
    scan_parser.add_argument(
        "--delay",
        type=int,
        default=500,
        help="Delay between requests in ms (default: 500)",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Request timeout in seconds (default: 30)",
    )
    scan_parser.add_argument(
        "--concurrent",
        type=int,
        default=3,
        help="Max concurrent requests (default: 3)",
    )
    scan_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print full report to stdout",
    )
    scan_parser.set_defaults(func=cmd_scan)
    
    # List command
    list_parser = subparsers.add_parser("list", help="List available payloads")
    list_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show all payload details",
    )
    list_parser.set_defaults(func=cmd_list)
    
    # Info command
    info_parser = subparsers.add_parser("info", help="Get info about a specific payload")
    info_parser.add_argument("payload_id", help="Payload ID (e.g., io-001)")
    info_parser.set_defaults(func=cmd_info)
    
    # Parse and execute
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return 0
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
