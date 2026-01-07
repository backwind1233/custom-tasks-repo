#!/usr/bin/env python3
"""
Guardrails Security Scanner for Task Files

Scans task.md files for:
- Prompt injection attempts
- Toxic/harmful content  
- Secrets/credentials
- Malicious patterns

Usage:
    python guardrails-scan.py                    # Scan all tasks
    python guardrails-scan.py tasks/my-task      # Scan specific folder
    python guardrails-scan.py --json             # Output JSON format
    
Requirements:
    pip install guardrails-ai transformers torch
    guardrails hub install hub://guardrails/detect_prompt_injection
    guardrails hub install hub://guardrails/toxic_language
    guardrails hub install hub://guardrails/secrets_present
"""

import os
import sys
import json
import re
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Optional

# Try to import guardrails components
try:
    from guardrails import Guard
    from guardrails.hub import DetectPromptInjection, ToxicLanguage, SecretsPresent
    GUARDRAILS_AVAILABLE = True
except ImportError:
    GUARDRAILS_AVAILABLE = False


@dataclass
class Finding:
    """Security finding dataclass"""
    severity: str
    rule_id: str
    rule_name: str
    description: str
    file: str
    line: int
    match: str


class GuardrailsScanner:
    """Scanner using Guardrails AI for prompt safety"""
    
    # Prompt injection patterns (critical severity)
    PROMPT_INJECTION_PATTERNS = [
        (r'ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?)', 'Instruction override'),
        (r'disregard\s+(all\s+)?(previous|above|prior)', 'Instruction disregard'),
        (r'forget\s+(all\s+)?(previous|above|prior|everything)', 'Memory wipe attempt'),
        (r'you\s+are\s+now\s+(a|an|the)', 'Role reassignment'),
        (r'pretend\s+(you\s+are|to\s+be)', 'Role pretending'),
        (r'act\s+as\s+(if|a|an|the)', 'Role acting'),
        (r'from\s+now\s+on,?\s+you', 'Temporal role change'),
        (r'new\s+instructions?:', 'New instruction injection'),
        (r'system\s*:\s*', 'System prompt injection'),
        (r'<\|?system\|?>', 'System tag injection'),
        (r'\[INST\]|\[\/INST\]', 'Instruction tag injection'),
        (r'###\s*(Human|Assistant|System):', 'Role marker injection'),
        (r'Do\s+not\s+follow\s+(the\s+)?(above|previous)', 'Negative instruction'),
        (r'override\s+(all\s+)?(safety|restrictions?|rules?)', 'Safety override'),
        (r'jailbreak|DAN|do\s+anything\s+now', 'Jailbreak attempt'),
        (r'developer\s+mode|god\s+mode|admin\s+mode', 'Privilege escalation'),
    ]
    
    # Dangerous command patterns (high severity)
    DANGEROUS_COMMAND_PATTERNS = [
        (r'rm\s+-rf\s+/', 'Recursive delete root'),
        (r'mkfs\s+', 'Filesystem format'),
        (r'dd\s+if=.+of=/dev/', 'Direct disk write'),
        (r'chmod\s+777\s+/', 'Dangerous permission change'),
        (r'curl.+\|\s*(sh|bash)', 'Remote code execution'),
        (r'wget.+\|\s*(sh|bash)', 'Remote code execution'),
        (r'eval\s*\(', 'Dynamic code execution'),
        (r'exec\s*\(', 'Process execution'),
    ]
    
    # Secret patterns (high severity)
    SECRET_PATTERNS = [
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\'${\[\]<]+["\']', 'Hardcoded password'),
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][^"\'${\[\]<]+["\']', 'Hardcoded API key'),
        (r'(?i)(secret|token)\s*[=:]\s*["\'][^"\'${\[\]<]+["\']', 'Hardcoded secret'),
        (r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}', 'Bearer token'),
        (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'Private key'),
        (r'ghp_[a-zA-Z0-9]{36}', 'GitHub PAT'),
        (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API key'),
    ]
    
    # Patterns to skip (placeholders)
    SKIP_PATTERNS = [
        r'<your-',
        r'\$\{',
        r'\$[A-Z_]+',  # Environment variables like $AWS_ACCESS_KEY
        r'your-.*-here',
        r'example',
        r'placeholder',
        r'xxx+',
        r'\*\*\*',
        r'AWS_ACCESS_KEY',  # Common placeholder names
        r'AWS_SECRET',
        r'AZURE_',
        r'my-bucket',
        r'my-container',
    ]
    
    def __init__(self):
        self.findings: List[Finding] = []
        self.guard = None
        
        if GUARDRAILS_AVAILABLE:
            try:
                self.guard = Guard().use_many(
                    DetectPromptInjection(on_fail="noop"),
                    ToxicLanguage(on_fail="noop"),
                    SecretsPresent(on_fail="noop"),
                )
            except Exception as e:
                print(f"Warning: Could not initialize Guardrails: {e}", file=sys.stderr)
    
    def should_skip(self, text: str) -> bool:
        """Check if text matches skip patterns (placeholders)"""
        for pattern in self.SKIP_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def scan_with_patterns(self, content: str, file_path: str) -> List[Finding]:
        """Scan using regex patterns"""
        findings = []
        lines = content.split('\n')
        
        # Prompt injection patterns (critical)
        for pattern, name in self.PROMPT_INJECTION_PATTERNS:
            for i, line in enumerate(lines, 1):
                for match in re.finditer(pattern, line, re.IGNORECASE):
                    if not self.should_skip(match.group()):
                        findings.append(Finding(
                            severity='critical',
                            rule_id='PROMPT_INJECTION',
                            rule_name=f'Prompt Injection: {name}',
                            description='Detected potential prompt injection attempt',
                            file=file_path,
                            line=i,
                            match=match.group()[:100]
                        ))
        
        # Dangerous command patterns (high)
        for pattern, name in self.DANGEROUS_COMMAND_PATTERNS:
            for i, line in enumerate(lines, 1):
                for match in re.finditer(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        severity='high',
                        rule_id='DANGEROUS_CMD',
                        rule_name=f'Dangerous Command: {name}',
                        description='Detected potentially dangerous command',
                        file=file_path,
                        line=i,
                        match=match.group()[:100]
                    ))
        
        # Secret patterns (high)
        for pattern, name in self.SECRET_PATTERNS:
            for i, line in enumerate(lines, 1):
                for match in re.finditer(pattern, line):
                    if not self.should_skip(match.group()):
                        findings.append(Finding(
                            severity='high',
                            rule_id='SECRET_DETECTED',
                            rule_name=f'Secret: {name}',
                            description='Detected potential hardcoded credential',
                            file=file_path,
                            line=i,
                            match=match.group()[:50] + '...'
                        ))
        
        return findings
    
    def scan_with_guardrails(self, content: str, file_path: str) -> List[Finding]:
        """Scan using Guardrails AI"""
        findings = []
        
        if not self.guard:
            return findings
        
        try:
            result = self.guard.validate(content)
            
            if result.validation_passed is False:
                for error in result.error_spans or []:
                    findings.append(Finding(
                        severity='critical',
                        rule_id='GUARDRAILS',
                        rule_name=f'Guardrails: {error.get("validator_name", "Unknown")}',
                        description=error.get('error_message', 'Validation failed'),
                        file=file_path,
                        line=1,
                        match=str(error.get('value', ''))[:100]
                    ))
        except Exception as e:
            print(f"Warning: Guardrails scan error for {file_path}: {e}", file=sys.stderr)
        
        return findings
    
    def scan_file(self, file_path: str) -> List[Finding]:
        """Scan a single file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading {file_path}: {e}", file=sys.stderr)
            return []
        
        findings = []
        
        # Pattern-based scanning (always run)
        findings.extend(self.scan_with_patterns(content, file_path))
        
        # Guardrails AI scanning (if available)
        findings.extend(self.scan_with_guardrails(content, file_path))
        
        return findings
    
    def scan_directory(self, directory: str, folders: Optional[List[str]] = None) -> dict:
        """Scan directory or specific folders"""
        tasks_dir = Path(directory) / 'tasks'
        
        if folders:
            # Scan specific folders
            for folder in folders:
                folder_path = tasks_dir / folder
                if folder_path.exists():
                    task_md = folder_path / 'task.md'
                    if task_md.exists():
                        self.findings.extend(self.scan_file(str(task_md)))
                    # Also scan other files in folder
                    for f in folder_path.glob('*'):
                        if f.is_file() and f.name != 'task.md':
                            self.findings.extend(self.scan_file(str(f)))
        else:
            # Scan all task folders
            if tasks_dir.exists():
                for task_folder in tasks_dir.iterdir():
                    if task_folder.is_dir():
                        task_md = task_folder / 'task.md'
                        if task_md.exists():
                            self.findings.extend(self.scan_file(str(task_md)))
                        # Also scan other files
                        for f in task_folder.glob('*'):
                            if f.is_file() and f.name != 'task.md':
                                self.findings.extend(self.scan_file(str(f)))
        
        return self.summarize()
    
    def summarize(self) -> dict:
        """Summarize findings"""
        summary = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'total': len(self.findings)
        }
        
        for finding in self.findings:
            summary[finding.severity].append(asdict(finding))
        
        return summary
    
    def generate_report(self, summary: dict) -> str:
        """Generate markdown report"""
        report = ['# 🛡️ Guardrails Security Scan Report\n']
        
        # Summary table
        report.append('## Summary\n')
        report.append('| Severity | Count |')
        report.append('|----------|-------|')
        report.append(f'| 🔴 Critical | {len(summary["critical"])} |')
        report.append(f'| 🟠 High | {len(summary["high"])} |')
        report.append(f'| 🟡 Medium | {len(summary["medium"])} |')
        report.append(f'| 🟢 Low | {len(summary["low"])} |')
        report.append(f'| **Total** | **{summary["total"]}** |\n')
        
        # Status
        if summary['critical'] or summary['high']:
            report.append('> ❌ **FAILED**: Critical or high severity issues found\n')
        elif summary['medium']:
            report.append('> ⚠️ **WARNING**: Medium severity issues found\n')
        else:
            report.append('> ✅ **PASSED**: No significant security issues found\n')
        
        # Guardrails status
        if GUARDRAILS_AVAILABLE:
            report.append('> 🛡️ Guardrails AI: **Active**\n')
        else:
            report.append('> 🛡️ Guardrails AI: *Not installed (using pattern-based fallback)*\n')
            report.append('> Install with: `pip install guardrails-ai && guardrails hub install hub://guardrails/detect_prompt_injection`\n')
        
        # Details
        severity_labels = {
            'critical': '🔴 Critical',
            'high': '🟠 High',
            'medium': '🟡 Medium',
            'low': '🟢 Low'
        }
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if summary[severity]:
                report.append(f'\n## {severity_labels[severity]} Issues\n')
                for finding in summary[severity]:
                    report.append(f'### {finding["rule_id"]}: {finding["rule_name"]}')
                    report.append(f'- **File:** {finding["file"]}:{finding["line"]}')
                    report.append(f'- **Description:** {finding["description"]}')
                    report.append(f'- **Match:** `{finding["match"]}`\n')
        
        return '\n'.join(report)
    
    def generate_json_report(self, summary: dict) -> str:
        """Generate JSON report"""
        return json.dumps({
            'passed': not (summary['critical'] or summary['high']),
            'guardrails_available': GUARDRAILS_AVAILABLE,
            'summary': {
                'critical': len(summary['critical']),
                'high': len(summary['high']),
                'medium': len(summary['medium']),
                'low': len(summary['low']),
                'total': summary['total']
            },
            'findings': [asdict(f) for f in self.findings]
        }, indent=2)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Guardrails Security Scanner for Task Files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python guardrails-scan.py                     # Scan all tasks
    python guardrails-scan.py aws-s3-to-azure     # Scan specific task
    python guardrails-scan.py --json              # Output JSON format
    python guardrails-scan.py -d /path/to/repo    # Specify directory
        """
    )
    parser.add_argument('-d', '--directory', default='..', help='Root directory (default: ..)')
    parser.add_argument('folders', nargs='*', help='Specific task folders to scan')
    parser.add_argument('--json', action='store_true', help='Output JSON format')
    
    args = parser.parse_args()
    
    scanner = GuardrailsScanner()
    
    print("🔍 Scanning tasks for security issues...\n", file=sys.stderr)
    
    summary = scanner.scan_directory(args.directory, args.folders if args.folders else None)
    
    if args.json:
        print(scanner.generate_json_report(summary))
    else:
        print(scanner.generate_report(summary))
    
    # Exit code
    if summary['critical'] or summary['high']:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
