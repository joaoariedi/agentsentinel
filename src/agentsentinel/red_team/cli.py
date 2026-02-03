
import argparse
import asyncio
from agentsentinel.red_team.scanner import AgentScanner
from agentsentinel.red_team import payloads
from agentsentinel.red_team.scanner import ScanStatus, ScanReport, VulnerabilityResult
from agentsentinel.red_team.reporter import ReportGenerator

import argparse
import asyncio
from datetime import datetime, timezone

async def main():
    parser = argparse.ArgumentParser(description="AgentSentinel Red Team Suite")
    parser.add_argument("--category", type=str, help="Filter payloads by category")
    parser.add_argument("--severity", type=str, help="Filter payloads by severity")
    parser.add_argument("--output", type=str, help="Output file path")
    parser.add_argument("--format", type=str, choices=["markdown", "json"], default="markdown", help="Output format (markdown or json)")
    parser.add_argument("--target_url", type=str, required=True, help="Target URL to scan")

    args = parser.parse_args()

    # Filter payloads
    scanner = AgentScanner()
    payloads_list = scanner.payload_library.get_all()
    if args.category:
        try:
            category_enum = payloads.PayloadCategory(args.category)
            payloads_list = [p for p in payloads_list if p.category == category_enum]
        except ValueError:
            print(f"Invalid category: {args.category}")
            return
    if args.severity:
        try:
            severity_enum = payloads.Severity(args.severity)
            payloads_list = [p for p in payloads_list if p.severity == severity_enum]
        except ValueError:
            print(f"Invalid severity: {args.severity}")
            return

    # Run scan
    scanner = AgentScanner()
    report = ScanReport(
        scan_id="redteam-" + datetime.now(timezone.utc).isoformat(),
        target_url=args.target_url,
        started_at=datetime.now(timezone.utc),
        results=[]
    )
    for payload in payloads_list:
        vuln_result = await scanner._test_payload(
            client=None,
            target_url=args.target_url,
            payload=payload,
            vuln_patterns=scanner._compile_patterns()[0],
            reject_patterns=scanner._compile_patterns()[1],
        )
        report.results.append(vuln_result)
    
    # Calculate security score, payloads_tested, vulnerabilities_found
    report.payloads_tested = len(report.results)
    report.vulnerabilities_found = len([r for r in report.results if r.vulnerable])
    
    vuln_weight = 0.0
    for vuln in report.results:
        if vuln.payload.severity == payloads.Severity.HIGH:
            vuln_weight += 15
        elif vuln.payload.severity == payloads.Severity.MEDIUM:
            vuln_weight += 8
        else:
            vuln_weight += 3  # LOW
            
    report.security_score = max(0.0, 100.0 - vuln_weight)

    # Generate report
    reporter = ReportGenerator(report)
    if args.format == "json":
        report_string = reporter.generate_json()
    else:
        report_string = reporter.generate_markdown()

    # Output report
    if args.output:
        with open(args.output, "w") as f:
            f.write(report_string)
    else:
        print(report_string)

if __name__ == "__main__":
    asyncio.run(main())
