"""
response_engine.py - Automated threat response and containment.

Generates platform-specific response commands for detected threats,
executes containment actions (with dry-run safety), and manages
response playbooks.
"""

from __future__ import annotations

import os
import platform
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

# ═══════════════════════════════════════════════════════════════════════════
# Platform-Specific Command Templates
# ═══════════════════════════════════════════════════════════════════════════

COMMAND_TEMPLATES: dict[ResponseAction, dict[Platform, str]] = {
    ResponseAction.BLOCK_IP: {
        Platform.WINDOWS: 'netsh advfirewall firewall add rule name="PcapMalAnalyzer Block {value}" dir=out action=block remoteip={value}',
        Platform.LINUX: "sudo iptables -A OUTPUT -d {value} -j DROP && sudo iptables -A INPUT -s {value} -j DROP",
        Platform.MACOS: "echo 'block in from any to {value}' | sudo pfctl -ef -",
    },
    ResponseAction.BLOCK_DOMAIN: {
        Platform.WINDOWS: 'Add-Content -Path "$env:SYSTEMROOT\\System32\\drivers\\etc\\hosts" "127.0.0.1 {value}"',
        Platform.LINUX: "echo '127.0.0.1 {value}' | sudo tee -a /etc/hosts",
        Platform.MACOS: "echo '127.0.0.1 {value}' | sudo tee -a /etc/hosts",
    },
    ResponseAction.BLOCK_PORT: {
        Platform.WINDOWS: 'netsh advfirewall firewall add rule name="PcapMalAnalyzer Block Port {value}" dir=out action=block protocol=tcp remoteport={value}',
        Platform.LINUX: "sudo iptables -A OUTPUT -p tcp --dport {value} -j DROP",
        Platform.MACOS: "echo 'block out proto tcp from any to any port {value}' | sudo pfctl -ef -",
    },
    ResponseAction.KILL_PROCESS: {
        Platform.WINDOWS: "taskkill /F /PID {value}",
        Platform.LINUX: "sudo kill -9 {value}",
        Platform.MACOS: "sudo kill -9 {value}",
    },
    ResponseAction.QUARANTINE_FILE: {
        Platform.WINDOWS: 'powershell -Command "Move-Item -Path \'{value}\' -Destination \'quarantine\' -Force"',
        Platform.LINUX: "sudo mv {value} /var/quarantine/ && sudo chmod 000 /var/quarantine/{filename}",
        Platform.MACOS: "sudo mv {value} /var/quarantine/ && sudo chmod 000 /var/quarantine/{filename}",
    },
    ResponseAction.FLUSH_DNS: {
        Platform.WINDOWS: "ipconfig /flushdns",
        Platform.LINUX: "sudo systemd-resolve --flush-caches 2>/dev/null || sudo resolvectl flush-caches 2>/dev/null || sudo /etc/init.d/nscd restart",
        Platform.MACOS: "sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder",
    },
    ResponseAction.ISOLATE_HOST: {
        Platform.WINDOWS: 'netsh interface set interface "Ethernet" disable 2>nul; netsh advfirewall set allprofiles state on',
        Platform.LINUX: "sudo iptables -P OUTPUT DROP && sudo iptables -P INPUT DROP && sudo iptables -A INPUT -i lo -j ACCEPT",
        Platform.MACOS: "sudo pfctl -d; echo 'block all' | sudo pfctl -ef -",
    },
    ResponseAction.CAPTURE_FORENSICS: {
        Platform.WINDOWS: "tasklist /v > forensics_processes.txt && netstat -ano > forensics_network.txt && ipconfig /all > forensics_network_config.txt",
        Platform.LINUX: "ps auxf > forensics_processes.txt && ss -tulnpa > forensics_network.txt && ip addr > forensics_network_config.txt",
        Platform.MACOS: "ps aux > forensics_processes.txt && lsof -i -P > forensics_network.txt && ifconfig > forensics_network_config.txt",
    },
    ResponseAction.ENABLE_LOGGING: {
        Platform.WINDOWS: 'wevtutil set-log Security /enabled:true /size:1gb /autobackup:true',
        Platform.LINUX: "sudo systemctl start auditd && sudo auditctl -w /etc/passwd -p wa",
        Platform.MACOS: "sudo launchctl load /System/Library/LaunchDaemons/com.apple.auditd.plist",
    },
}


class ResponseEngine:
    """Generates and optionally executes response plans for detected threats.

    Safety: All commands default to DRY-RUN mode.  Explicit confirmation
    is required for actual execution.

    Usage::

        engine = ResponseEngine(dry_run=True)
        plan = engine.generate_plan(alerts, damage_assessment)
        engine.execute_plan(plan)  # only runs if dry_run=False
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
                name="Ransomware Response",
                description="Immediate containment for ransomware activity",
                trigger_conditions=["ransomware", "encryption", "ransom"],
                severity_threshold=Severity.CRITICAL,
                commands=[
                    self._make_cmd(ResponseAction.ISOLATE_HOST, "Isolate host from network"),
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
                description="Respond to credential harvesting or theft",
                trigger_conditions=["credential", "password", "hash_dump"],
                severity_threshold=Severity.HIGH,
                commands=[
                    self._make_cmd(ResponseAction.CAPTURE_FORENSICS, "Capture memory artifacts"),
                    self._make_cmd(ResponseAction.RESET_CREDENTIALS, "Reset compromised credentials"),
                    self._make_cmd(ResponseAction.ENABLE_LOGGING, "Enable auth logging"),
                    self._make_cmd(ResponseAction.GENERATE_REPORT, "Generate report"),
                ],
                tags=["credentials", "identity", "containment"],
            ),
            Playbook(
                name="Data Exfiltration Response",
                description="Contain suspected data exfiltration",
                trigger_conditions=["exfiltration", "data_loss", "data_theft"],
                severity_threshold=Severity.HIGH,
                commands=[
                    self._make_cmd(ResponseAction.BLOCK_IP, "Block exfiltration endpoint"),
                    self._make_cmd(ResponseAction.CAPTURE_FORENSICS, "Capture forensic evidence"),
                    self._make_cmd(ResponseAction.GENERATE_REPORT, "Generate report"),
                ],
                tags=["exfiltration", "data", "containment"],
            ),
        ]

    def _make_cmd(self, action: ResponseAction, description: str, value: str = "") -> ResponseCommand:
        templates = COMMAND_TEMPLATES.get(action, {})
        cmd_str = templates.get(self._current_platform, f"[{action.value}]")
        if value:
            cmd_str = cmd_str.replace("{value}", value)
        return ResponseCommand(
            action=action,
            platform=self._current_platform,
            command_str=cmd_str,
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

        all_commands: list[ResponseCommand] = []
        matched_playbooks: list[Playbook] = []

        # Match alerts to playbooks
        for alert in alerts:
            for pb in self._playbooks:
                if any(cond in alert.title.lower() or cond in alert.description.lower()
                       for cond in pb.trigger_conditions):
                    if alert.severity.numeric >= pb.severity_threshold.numeric:
                        matched_playbooks.append(pb)

        # Add playbook commands
        for pb in matched_playbooks:
            all_commands.extend(pb.commands)
            logger.info("Matched playbook: %s", pb.name)

        # Add IP blocking commands
        if blocked_ips:
            for ip in blocked_ips:
                all_commands.append(self._make_cmd(
                    ResponseAction.BLOCK_IP, f"Block malicious IP: {ip}", ip,
                ))

        # Add process kill commands
        if killed_pids:
            for pid in killed_pids:
                all_commands.append(self._make_cmd(
                    ResponseAction.KILL_PROCESS, f"Kill malicious process PID={pid}", str(pid),
                ))

        # Assessment-driven commands
        if assessment:
            if assessment.severity == Severity.CRITICAL:
                all_commands.append(self._make_cmd(
                    ResponseAction.ISOLATE_HOST, "Emergency host isolation",
                ))
                all_commands.append(self._make_cmd(
                    ResponseAction.CAPTURE_FORENSICS, "Full forensic capture",
                ))
                all_commands.append(self._make_cmd(
                    ResponseAction.NOTIFY_ADMIN, "Escalate to CISO/SOC lead",
                ))

            if assessment.data_exfiltrations:
                for exfil in assessment.data_exfiltrations[:5]:
                    if exfil.destination_ip:
                        all_commands.append(self._make_cmd(
                            ResponseAction.BLOCK_IP,
                            f"Block exfil destination: {exfil.destination_ip}",
                            exfil.destination_ip,
                        ))

            # Always include forensic capture and reporting
            all_commands.append(self._make_cmd(
                ResponseAction.CAPTURE_FORENSICS, "Preventive forensic capture",
            ))
            all_commands.append(self._make_cmd(
                ResponseAction.GENERATE_REPORT, "Generate incident report",
            ))

        # Deduplicate
        seen_actions: set[str] = set()
        unique_commands: list[ResponseCommand] = []
        for cmd in all_commands:
            key = f"{cmd.action.value}:{cmd.command_str}"
            if key not in seen_actions:
                seen_actions.add(key)
                unique_commands.append(cmd)

        plan.commands = unique_commands
        plan.severity = max(
            (a.severity for a in alerts), default=Severity.LOW, key=lambda s: s.numeric,
        )
        plan.summary = (
            f"Response plan: {len(unique_commands)} commands generated from "
            f"{len(alerts)} alert(s), severity={plan.severity.value}"
        )

        logger.info("Response plan generated: %d commands", len(unique_commands))
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
                    result = subprocess.run(
                        cmd.command_str, shell=True, capture_output=True,
                        text=True, timeout=30,
                    )
                    cmd.execution_status = "executed" if result.returncode == 0 else "failed"
                    cmd.execution_result = result.stdout or result.stderr
                    cmd.executed_at = datetime.now()

                    if result.returncode == 0:
                        plan.executed_count += 1
                        logger.info("Executed: %s", cmd.description)
                    else:
                        plan.failed_count += 1
                        logger.error("Failed: %s - %s", cmd.description, result.stderr)
                except subprocess.TimeoutExpired:
                    cmd.execution_status = "failed"
                    cmd.execution_result = "Command timed out after 30s"
                    plan.failed_count += 1
                except Exception as exc:
                    cmd.execution_status = "failed"
                    cmd.execution_result = str(exc)
                    plan.failed_count += 1
                    logger.error("Command execution error: %s", exc)

        plan.summary = (
            f"Executed: {plan.executed_count}, Failed: {plan.failed_count}, "
            f"Skipped: {plan.skipped_count}"
        )
        return plan

    def get_available_playbooks(self) -> list[Playbook]:
        return list(self._playbooks)

    def get_commands_summary(self, plan: ResponsePlan) -> str:
        """Return a human-readable summary of planned commands."""
        lines = [f"Response Plan ({len(plan.commands)} commands):"]
        for i, cmd in enumerate(plan.commands, 1):
            status = "DRY-RUN" if cmd.execution_status == "dry_run" else cmd.execution_status
            lines.append(f"  {i}. [{status}] {cmd.action.value}: {cmd.description}")
            lines.append(f"     Platform: {cmd.platform.value}")
            lines.append(f"     Command: {cmd.command_str[:100]}")
        return "\n".join(lines)
