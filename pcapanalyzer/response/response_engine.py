"""
response_engine.py - Automated threat response and containment.

Generates platform-specific response commands for detected threats,
executes containment actions (with dry-run safety), and manages
response playbooks.
"""

from __future__ import annotations

import os
import platform
import shlex
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from .. import config
from ..models import (
    ResponseCommand, ResponsePlan, ResponseAction, Playbook,
    Alert, AlertGroup, DamageAssessment, Severity, Platform,
)
from ..utils import get_logger, ensure_directory

logger = get_logger("response_engine")

# ════════════════════════════════════════════════════════════════════════════
# Platform-Specific Command Templates (argument lists, not shell strings)
# ════════════════════════════════════════════════════════════════════════════

COMMAND_TEMPLATES: dict[ResponseAction, dict[Platform, list[str]]] = {
    ResponseAction.BLOCK_IP: {
        Platform.WINDOWS: ["netsh", "advfirewall", "firewall", "add", "rule", "name={name}", "dir=out", "action=block", "remoteip={value}"],
        Platform.LINUX: ["iptables", "-A", "OUTPUT", "-d", "{value}", "-j", "DROP"],
        Platform.MACOS: ["pfctl", "-t", "blocklist", "-T", "add", "{value}"],
    },
    ResponseAction.BLOCK_DOMAIN: {
        Platform.WINDOWS: ["powershell", "-Command", "Add-Content -Path '$env:SYSTEMROOT\\System32\\drivers\\etc\\hosts' -Value '127.0.0.1 {value}'"],
        Platform.LINUX: ["sh", "-c", "echo '127.0.0.1 {value}' >> /etc/hosts"],
        Platform.MACOS: ["sh", "-c", "echo '127.0.0.1 {value}' >> /etc/hosts"],
    },
    ResponseAction.BLOCK_PORT: {
        Platform.WINDOWS: ["netsh", "advfirewall", "firewall", "add", "rule", "name={name}", "dir=out", "action=block", "protocol=tcp", "remoteport={value}"],
        Platform.LINUX: ["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "{value}", "-j", "DROP"],
        Platform.MACOS: ["pfctl", "-t", "blocklist", "-T", "add", "port={value}"],
    },
    ResponseAction.KILL_PROCESS: {
        Platform.WINDOWS: ["taskkill", "/F", "/PID", "{value}"],
        Platform.LINUX: ["kill", "-9", "{value}"],
        Platform.MACOS: ["kill", "-9", "{value}"],
    },
    ResponseAction.QUARANTINE_FILE: {
        Platform.WINDOWS: ["powershell", "-Command", "Move-Item -Path '{value}' -Destination 'quarantine' -Force"],
        Platform.LINUX: ["mv", "{value}", "quarantine/"],
        Platform.MACOS: ["mv", "{value}", "quarantine/"],
    },
    ResponseAction.ISOLATE_HOST: {
        Platform.WINDOWS: ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"],
        Platform.LINUX: ["iptables", "-P", "INPUT", "DROP"],
        Platform.MACOS: ["pfctl", "-e"],
    },
    ResponseAction.CAPTURE_FORENSICS: {
        Platform.WINDOWS: ["powershell", "-Command", "Compress-Archive -Path 'C:\\Windows\\Temp\\*' -DestinationPath 'forensics.zip'"],
        Platform.LINUX: ["tar", "-czf", "forensics.tar.gz", "/var/log", "/tmp"],
        Platform.MACOS: ["tar", "-czf", "forensics.tar.gz", "/var/log", "/tmp"],
    },
    ResponseAction.NOTIFY_ADMIN: {
        Platform.ANY: ["echo", "ALERT: {description}"],
    },
    ResponseAction.GENERATE_REPORT: {
        Platform.ANY: ["echo", "Generating report for: {description}"],
    },
    ResponseAction.ENABLE_LOGGING: {
        Platform.WINDOWS: ["wevtutil", "sl", "Security", "/e:true"],
        Platform.LINUX: ["systemctl", "restart", "rsyslog"],
        Platform.MACOS: ["log", "config", "--mode", "level: debug"],
    },
}


def _sanitize_value(value: str) -> str:
    """Sanitize input value to prevent command injection."""
    # Allow only alphanumeric, dots, colons, hyphens, underscores, slashes
    import re
    return re.sub(r'[^a-zA-Z0-9.:_\-/]', '', str(value))


def _sanitize_ip(ip: str) -> str:
    """Validate and sanitize IP address."""
    import re
    # IPv4
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            return ip
    # IPv6 (simplified)
    if re.match(r'^[0-9a-fA-F:]+$', ip):
        return ip
    return ""


def _sanitize_domain(domain: str) -> str:
    """Validate and sanitize domain name."""
    import re
    if re.match(r'^[a-zA-Z0-9.-]+$', domain):
        return domain
    return ""


def _sanitize_pid(pid: str) -> str:
    """Validate and sanitize PID."""
    if pid.isdigit() and 1 <= int(pid) <= 4194304:
        return pid
    return ""


def _sanitize_port(port: str) -> str:
    """Validate and sanitize port number."""
    if port.isdigit() and 1 <= int(port) <= 65535:
        return port
    return ""


def _sanitize_path(path: str) -> str:
    """Validate and sanitize file path."""
    import re
    # Allow alphanumeric, dots, slashes, backslashes, colons, hyphens, underscores
    if re.match(r'^[a-zA-Z0-9._\\/-]+$', path):
        # Prevent directory traversal
        if '..' not in path and not path.startswith('/') and not (len(path) > 1 and path[1] == ':'):
            return path
    return ""


class ResponseEngine:
    """Generates and optionally executes response plans for detected threats.

    Safety: All commands default to DRY-RUN mode.  Explicit confirmation
    is required for actual execution.
    """

    def __init__(self, dry_run: bool = config.RESPONSE_DRY_RUN_DEFAULT) -> None:
        self.dry_run = dry_run
        self._current_platform = self._detect_platform()
        self._playbooks: list[Playbook] = []
        self._load_default_playbooks()

    def _detect_platform(self) -> Platform:
        system = platform.system().lower()
        return {
            "windows": Platform.WINDOWS,
            "linux": Platform.LINUX,
            "darwin": Platform.MACOS,
        }.get(system, Platform.ANY)

    def _load_default_playbooks(self) -> None:
        """Load built-in playbooks for common threat scenarios."""
        self._playbooks = [
            Playbook(
                name="Ransomware Containment",
                description="Immediate containment for ransomware activity",
                trigger_conditions=["ransomware", "encryption", "file_modification"],
                severity_threshold=Severity.CRITICAL,
                commands=[
                    self._make_cmd(ResponseAction.ISOLATE_HOST, "Isolate host from network"),
                    self._make_cmd(ResponseAction.KILL_PROCESS, "Kill suspicious processes"),
                    self._make_cmd(ResponseAction.CAPTURE_FORENSICS, "Capture forensic evidence"),
                    self._make_cmd(ResponseAction.NOTIFY_ADMIN, "Notify security team"),
                    self._make_cmd(ResponseAction.GENERATE_REPORT, "Generate incident report"),
                ],
                tags=["ransomware", "critical", "containment"],
            ),
            Playbook(
                name="C2 Communication Response",
                description="Block identified command-and-control channels",
                trigger_conditions=["c2", "command_and_control", "beacon"],
                severity_threshold=Severity.HIGH,
                commands=[
                    self._make_cmd(ResponseAction.CAPTURE_FORENSICS, "Capture process state"),
                    self._make_cmd(ResponseAction.ENABLE_LOGGING, "Enable enhanced logging"),
                    self._make_cmd(ResponseAction.GENERATE_REPORT, "Generate report"),
                ],
                tags=["c2", "network", "containment"],
            ),
            Playbook(
                name="Credential Theft Response",
                description="Respond to credential harvesting activity",
                trigger_conditions=["credential_access", "credential_dumping", "mimikatz"],
                severity_threshold=Severity.HIGH,
                commands=[
                    self._make_cmd(ResponseAction.KILL_PROCESS, "Kill credential dumping process"),
                    self._make_cmd(ResponseAction.NOTIFY_ADMIN, "Notify security team"),
                    self._make_cmd(ResponseAction.GENERATE_REPORT, "Generate report"),
                ],
                tags=["credentials", "privilege_escalation", "containment"],
            ),
        ]

    def _make_cmd(self, action: ResponseAction, description: str, value: str = "") -> ResponseCommand:
        templates = COMMAND_TEMPLATES.get(action, {})
        template = templates.get(self._current_platform) or templates.get(Platform.ANY)
        if not template:
            cmd_str = f"[{action.value}]"
            cmd_list = [cmd_str]
        else:
            # Sanitize the value based on action type
            safe_value = ""
            if value:
                if action == ResponseAction.BLOCK_IP:
                    safe_value = _sanitize_ip(value)
                elif action == ResponseAction.BLOCK_DOMAIN:
                    safe_value = _sanitize_domain(value)
                elif action == ResponseAction.KILL_PROCESS:
                    safe_value = _sanitize_pid(value)
                elif action == ResponseAction.BLOCK_PORT:
                    safe_value = _sanitize_port(value)
                elif action == ResponseAction.QUARANTINE_FILE:
                    safe_value = _sanitize_path(value)
                else:
                    safe_value = _sanitize_value(value)
            
            if safe_value or action in (ResponseAction.NOTIFY_ADMIN, ResponseAction.GENERATE_REPORT):
                cmd_list = []
                for arg in template:
                    if "{value}" in arg and safe_value:
                        cmd_list.append(arg.replace("{value}", safe_value))
                    elif "{name}" in arg:
                        cmd_list.append(arg.replace("{name}", f"xPredatorBlock-{safe_value[:20]}"))
                    elif "{description}" in arg:
                        cmd_list.append(arg.replace("{description}", description))
                    else:
                        cmd_list.append(arg)
            else:
                # No valid value provided, return placeholder
                cmd_list = [f"# {action.value}: {description} (no valid value)"]

        return ResponseCommand(
            action=action,
            platform=self._current_platform,
            command_str=" ".join(cmd_list),
            command_args=cmd_list if len(cmd_list) > 0 else None,
            description=description,
            requires_elevation=action.value in config.RESPONSE_ELEVATION_REQUIRED,
            reversible=True,
        )

    def generate_plan(
        self,
        alerts: list[Alert],
        assessment: Optional[DamageAssessment] = None,
        blocked_ips: Optional[list[str]] = None,
        killed_pids: Optional[list[int]] = None,
    ) -> ResponsePlan:
        """Generate a complete response plan from alerts and assessment."""
        plan = ResponsePlan(
            severity=Severity.INFO,
            generated_at=datetime.now(),
        )

        # Determine overall severity
        max_severity = max((a.severity for a in alerts), default=Severity.INFO)
        plan.severity = max_severity

        # Process alerts
        for alert in alerts:
            if alert.severity in (Severity.CRITICAL, Severity.HIGH):
                # Block IPs from high/critical alerts
                if alert.src_ip and alert.src_ip not in (blocked_ips or []):
                    plan.commands.append(self._make_cmd(
                        ResponseAction.BLOCK_IP,
                        f"Block source IP from alert: {alert.title}",
                        alert.src_ip,
                    ))
                if alert.dst_ip and alert.dst_ip not in (blocked_ips or []):
                    plan.commands.append(self._make_cmd(
                        ResponseAction.BLOCK_IP,
                        f"Block destination IP from alert: {alert.title}",
                        alert.dst_ip,
                    ))

        # Check for matching playbooks
        for playbook in self._playbooks:
            if playbook.severity_threshold.numeric <= max_severity.numeric:
                for condition in playbook.trigger_conditions:
                    if any(condition.lower() in alert.title.lower() or
                           condition.lower() in alert.description.lower()
                           for alert in alerts):
                        # Add playbook commands
                        for cmd in playbook.commands:
                            plan.commands.append(cmd)
                        break

        # Add assessment-based commands
        if assessment:
            for vector in assessment.vectors:
                if vector.score >= 7.0:
                    plan.commands.append(self._make_cmd(
                        ResponseAction.NOTIFY_ADMIN,
                        f"High impact vector: {vector.vector_name} (score: {vector.score:.1f})",
                    ))

        return plan

    def execute_plan(self, plan: ResponsePlan) -> ResponsePlan:
        """Execute a response plan. Respects dry_run flag."""
        for cmd in plan.commands:
            if self.dry_run:
                cmd.execution_status = "dry_run"
                cmd.execution_result = f"[DRY RUN] Would execute: {cmd.command_str}"
                logger.info("[DRY RUN] %s: %s", cmd.action.value, cmd.description)
            else:
                try:
                    if cmd.command_args:
                        # Use list form (no shell=True)
                        result = subprocess.run(
                            cmd.command_args,
                            capture_output=True,
                            text=True,
                            timeout=30,
                        )
                    else:
                        result = subprocess.run(
                            cmd.command_str,
                            shell=True,
                            capture_output=True,
                            text=True,
                            timeout=30,
                        )
                    cmd.execution_status = "executed" if result.returncode == 0 else "failed"
                    cmd.execution_result = result.stdout or result.stderr
                    cmd.executed_at = datetime.now()

                    if result.returncode == 0:
                        plan.executed_count += 1
                        logger.info("Executed: %s", cmd.description)
                    else:
                        logger.error("Failed to execute: %s - %s", cmd.description, result.stderr)

                except subprocess.TimeoutExpired:
                    cmd.execution_status = "timeout"
                    cmd.execution_result = "Command timed out after 30 seconds"
                    logger.error("Timeout executing: %s", cmd.description)
                except Exception as exc:
                    cmd.execution_status = "error"
                    cmd.execution_result = str(exc)
                    logger.error("Error executing %s: %s", cmd.description, exc)

        return plan

    def get_available_playbooks(self) -> list[Playbook]:
        return self._playbooks.copy()

    def get_commands_summary(self, plan: ResponsePlan) -> str:
        lines = [f"Response Plan ({len(plan.commands)} commands):"]
        for i, cmd in enumerate(plan.commands, 1):
            status = cmd.execution_status or "pending"
            lines.append(f"  {i}. [{cmd.action.value}] {cmd.description} - {status}")
        return "\n".join(lines)