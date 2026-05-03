import argparse
import ipaddress
import json
import math
import shlex
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

from nn import AISOC
from notify import (
    AlertEvent,
    alert_title,
    build_alert_id,
    build_notifier_from_env,
    confidence_from_row,
    mitre_mapping_from_vulnerability,
    rule_name_from_vulnerability,
    watch_csv_for_alerts,
)


@dataclass
class CommandPlan:
    row_index: int
    action: str
    severity: str
    probability: float
    command: list[str]
    reason: str


class AutoSOCHeart:
    def __init__(
        self,
        model_path="artifacts/aisoc_model.joblib",
        work_dir="artifacts/autosoc",
        execute=False,
        assume_yes=False,
        allow_containment=False,
        max_actions=10,
        notifier=None,
    ):
        self.model_path = Path(model_path)
        self.work_dir = Path(work_dir)
        self.execute = execute
        self.assume_yes = assume_yes
        self.allow_containment = allow_containment
        self.max_actions = max_actions
        self.notifier = notifier or build_notifier_from_env()
        self.soc = self._load_brain()

    def wake(self, csv_path, output_path="artifacts/autosoc_predictions.csv", rows=None):
        self.work_dir.mkdir(parents=True, exist_ok=True)
        print("autoSOC heart online.")
        print(f"Loaded brain: {self.model_path}")
        print(f"Mode: {'execute-with-approval' if self.execute else 'dry-run'}")

        predictions = self.soc.predict_csv(csv_path, output_path=output_path, max_rows=rows)
        actionable = predictions[predictions["soc_action"] != "monitor"].copy()

        if actionable.empty:
            print("No action needed. Heartbeat steady.")
            return predictions

        print(f"Actionable rows: {len(actionable)}")
        for row_index, row in actionable.head(self.max_actions).iterrows():
            self._handle_row(row_index, row)

        skipped = len(actionable) - min(len(actionable), self.max_actions)
        if skipped > 0:
            print(f"Skipped {skipped} additional actionable rows because --max-actions is {self.max_actions}.")

        return predictions

    def _handle_row(self, row_index, row):
        threat = self._describe_threat(row_index, row)
        ticket_path = self._write_ticket(row_index, row, threat)
        print(f"\nTicket created: {ticket_path}")
        print(
            "Decision:",
            row["soc_action"],
            f"severity={row['soc_severity']}",
            f"probability={float(row['soc_attack_probability']):.4f}",
        )
        print(f"Vulnerability: {threat['vulnerability']}")
        self._notify_human(row_index, row, ticket_path, threat)

        plans = self._build_command_plans(row_index, row, ticket_path)
        for plan in plans:
            self._review_and_maybe_execute(plan)

    def _build_command_plans(self, row_index, row, ticket_path):
        action = str(row["soc_action"])
        severity = str(row["soc_severity"])
        probability = float(row["soc_attack_probability"])
        reason = str(row["soc_reason"])
        message = (
            f"autoSOC {severity} {action}: row={row_index} "
            f"probability={probability:.4f} ticket={ticket_path}"
        )

        plans = []
        if action == "analyst_review":
            plans.append(
                CommandPlan(
                    row_index=row_index,
                    action=action,
                    severity=severity,
                    probability=probability,
                    command=["logger", "-p", "user.notice", "-t", "autoSOC", message],
                    reason=reason,
                )
            )
        elif action == "escalate_ticket":
            plans.append(
                CommandPlan(
                    row_index=row_index,
                    action=action,
                    severity=severity,
                    probability=probability,
                    command=["logger", "-p", "user.warning", "-t", "autoSOC", message],
                    reason=reason,
                )
            )
        elif action == "containment_review":
            plans.append(
                CommandPlan(
                    row_index=row_index,
                    action=action,
                    severity=severity,
                    probability=probability,
                    command=["logger", "-p", "user.crit", "-t", "autoSOC", message],
                    reason=reason,
                )
            )

            source_ip = self._extract_source_ip(row)
            if self.allow_containment and source_ip is not None:
                plans.append(
                    CommandPlan(
                        row_index=row_index,
                        action="block_source_ip",
                        severity="critical",
                        probability=probability,
                        command=[
                            "sudo",
                            "iptables",
                            "-I",
                            "INPUT",
                            "-s",
                            source_ip,
                            "-j",
                            "DROP",
                            "-m",
                            "comment",
                            "--comment",
                            f"autoSOC row={row_index} probability={probability:.4f}",
                        ],
                        reason="Containment was explicitly enabled and a source IP was present.",
                    )
                )
            elif self.allow_containment:
                print("Containment enabled, but no source IP column was found for this row.")

        return plans

    def _review_and_maybe_execute(self, plan):
        command_text = shlex.join(plan.command)
        print("\nProposed Linux command:")
        print(f"$ {command_text}")
        print(f"Reason: {plan.reason}")

        if not self._command_allowed(plan.command):
            print("Blocked: command is not in the autoSOC allowlist.")
            return

        if not self.execute:
            print("Dry-run only. Add --execute to request terminal approval for command execution.")
            return

        if not self.assume_yes:
            answer = input("Type EXECUTE to run this command, or press Enter to skip: ").strip()
            if answer != "EXECUTE":
                print("Skipped.")
                return

        result = subprocess.run(plan.command, capture_output=True, text=True, timeout=30, check=False)
        print(f"Exit code: {result.returncode}")
        if result.stdout.strip():
            print(result.stdout.strip())
        if result.stderr.strip():
            print(result.stderr.strip())

    def _command_allowed(self, command):
        if not command:
            return False

        if command[0] == "logger":
            return True

        if (
            self.allow_containment
            and len(command) >= 8
            and command[0] == "sudo"
            and command[1] == "iptables"
            and command[2] == "-I"
            and command[3] == "INPUT"
            and "-s" in command
            and "-j" in command
            and "DROP" in command
        ):
            return True

        return False

    def _write_ticket(self, row_index, row, threat):
        tickets_dir = self.work_dir / "tickets"
        tickets_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        action = str(row["soc_action"])
        ticket_path = tickets_dir / f"{timestamp}_row-{row_index}_{action}.json"
        payload = {
            "created_at": datetime.now(UTC).isoformat(),
            "row_index": int(row_index),
            "action": action,
            "severity": str(row["soc_severity"]),
            "attack_probability": float(row["soc_attack_probability"]),
            "requires_approval": bool(row["soc_requires_approval"]),
            "dry_run": bool(row["soc_dry_run"]),
            "reason": str(row["soc_reason"]),
            "vulnerability": threat["vulnerability"],
            "affected_asset": threat["affected_asset"],
            "evidence": threat["evidence"],
            "recommended_action": threat["recommended_action"],
            "row": self._json_safe_row(row),
        }
        ticket_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return ticket_path

    def _json_safe_row(self, row):
        safe = {}
        for key, value in row.to_dict().items():
            if isinstance(value, float) and math.isnan(value):
                safe[key] = None
            elif pd.isna(value):
                safe[key] = None
            elif hasattr(value, "item"):
                safe[key] = value.item()
            else:
                safe[key] = value
        return safe

    def _extract_source_ip(self, row):
        candidates = [
            "src_ip",
            "source_ip",
            "Source IP",
            "Src IP",
            "source",
            "src",
        ]
        for candidate in candidates:
            if candidate not in row:
                continue
            value = str(row[candidate]).strip()
            try:
                return str(ipaddress.ip_address(value))
            except ValueError:
                continue
        return None

    def _notify_human(self, row_index, row, ticket_path, threat):
        self.notifier.send(
            AlertEvent(
                alert_id=build_alert_id(row_index, threat["vulnerability"], row),
                title=alert_title(
                    threat["vulnerability"],
                    threat["affected_asset"],
                    threat.get("destination_service"),
                ),
                severity=str(row["soc_severity"]),
                action=str(row["soc_action"]),
                reason=str(row["soc_reason"]),
                rule_name=rule_name_from_vulnerability(threat["vulnerability"]),
                vulnerability=threat["vulnerability"],
                confidence=confidence_from_row(row, float(row["soc_attack_probability"])),
                tactic=threat["tactic"],
                technique=threat["technique"],
                recommended_action=threat["recommended_action"],
                affected_asset=threat["affected_asset"],
                source_asset=threat["source_asset"],
                destination_asset=threat["destination_asset"],
                destination_service=threat["destination_service"],
                evidence=threat["evidence"],
                probability=float(row["soc_attack_probability"]),
                row_index=int(row_index),
                ticket_path=str(ticket_path),
                details={
                    "prediction": str(row.get("soc_prediction", "")),
                    "requires_approval": bool(row.get("soc_requires_approval", False)),
                },
            )
        )

    def _describe_threat(self, row_index, row):
        probability = float(row["soc_attack_probability"])
        action = str(row["soc_action"])
        vulnerability = self._vulnerability_from_row(row)
        source_asset = self._source_asset(row)
        destination_asset = self._destination_asset(row)
        destination_service = self._destination_service(row)
        affected_asset = destination_asset or destination_service or "unknown destination"
        tactic, technique = mitre_mapping_from_vulnerability(vulnerability)
        evidence = self._evidence_from_row(row_index, row, vulnerability)
        recommended_action = self._recommended_action(action, vulnerability)
        evidence.append(f"model attack probability: {probability:.4f}")
        evidence.append(f"planned autoSOC action: {action}")
        return {
            "vulnerability": vulnerability,
            "affected_asset": affected_asset,
            "source_asset": source_asset,
            "destination_asset": destination_asset,
            "destination_service": destination_service,
            "tactic": tactic,
            "technique": technique,
            "evidence": evidence,
            "recommended_action": recommended_action,
        }

    def _vulnerability_from_row(self, row):
        label = self._clean_text(row.get("Label", ""))
        if label and label.upper() != "BENIGN":
            return label

        port = self._number(row.get("Destination Port"))
        syn = self._number(row.get("SYN Flag Count"))
        fin = self._number(row.get("FIN Flag Count"))
        rst = self._number(row.get("RST Flag Count"))
        fwd_packets = self._number(row.get("Total Fwd Packets"))
        bwd_packets = self._number(row.get("Total Backward Packets"))

        if port in {80, 443, 8080, 8443}:
            return "Possible web application attack"
        if port == 22:
            return "Possible SSH brute-force or unauthorized access attempt"
        if port == 3389:
            return "Possible RDP brute-force or remote access attempt"
        if port in {1433, 3306, 5432}:
            return "Possible database exposure or injection attempt"
        if port in {389, 636}:
            return "Possible directory service attack"
        if port == 53:
            return "Possible DNS abuse or tunneling attempt"
        if syn > 0 and bwd_packets == 0:
            return "Possible SYN scan or half-open connection attempt"
        if rst > 0 or fin > 0:
            return "Possible network scan or probing attempt"
        if fwd_packets > 100 and bwd_packets == 0:
            return "Possible one-way flood or reconnaissance attempt"
        return "Suspicious network flow"

    def _evidence_from_row(self, row_index, row, vulnerability):
        evidence = [f"row index: {row_index}", f"vulnerability assessment: {vulnerability}"]
        label = self._clean_text(row.get("Label", ""))
        if label:
            evidence.append(f"csv label: {label}")

        fields = [
            "Destination Port",
            "Flow Duration",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Flow Bytes/s",
            "Flow Packets/s",
            "SYN Flag Count",
            "RST Flag Count",
            "PSH Flag Count",
            "ACK Flag Count",
        ]
        for field in fields:
            if field in row:
                evidence.append(f"{field}: {row[field]}")
        return evidence

    def _source_asset(self, row):
        for field in ("src_ip", "source_ip", "Source IP", "Src IP"):
            value = self._clean_text(row.get(field, ""))
            if value:
                return value
        return "unknown source"

    def _destination_asset(self, row):
        for field in ("dst_ip", "destination_ip", "Destination IP", "Dst IP"):
            value = self._clean_text(row.get(field, ""))
            if value:
                return value
        return None

    def _destination_service(self, row):
        port = self._clean_text(row.get("Destination Port", ""))
        if port:
            try:
                port_int = int(float(port))
            except ValueError:
                return f"destination port {port}"
            service = {
                21: "FTP",
                22: "SSH",
                53: "DNS",
                80: "HTTP",
                137: "NetBIOS Name Service",
                389: "LDAP",
                443: "HTTPS",
                445: "SMB",
                1433: "MSSQL",
                3306: "MySQL",
                3389: "RDP",
                5353: "mDNS",
                8080: "HTTP alternate",
                8443: "HTTPS alternate",
            }.get(port_int, "unknown service")
            return f"{service} on port {port_int}"
        return None

    def _recommended_action(self, action, vulnerability):
        if action == "containment_review":
            return "Immediately review the ticket, verify the source, and approve containment only if the traffic is confirmed malicious."
        if action == "escalate_ticket":
            return "Escalate to the analyst, inspect related flows, and check the affected service for compromise indicators."
        if action == "analyst_review":
            return "Review the flow details and compare with recent normal traffic before taking response action."
        return f"Monitor for repeat activity related to {vulnerability}."

    def _clean_text(self, value):
        if value is None or pd.isna(value):
            return ""
        text = str(value).replace("\ufffd", "-")
        return " ".join(text.split())

    def _number(self, value):
        try:
            if value is None or pd.isna(value):
                return 0
            return float(value)
        except (TypeError, ValueError):
            return 0

    def _load_brain(self):
        try:
            return AISOC.load_artifacts(self.model_path)
        except Exception as exc:
            project_dir = Path(__file__).resolve().parent
            venv_python = project_dir / ".venv" / "bin" / "python"
            message = f"""
autoSOC could not load the saved brain:
  {self.model_path}

Reason:
  {type(exc).__name__}: {exc}

This usually means the .joblib model was trained with a different Python,
NumPy, or scikit-learn version than the one running autoSOC.

Fix it by retraining the model inside this Linux environment:
  cd "{project_dir}"
  "{venv_python}" nn.py --model-out artifacts/aisoc_model.joblib

Then wake autoSOC again:
  autoSOC --csv cybersecurity.csv
"""
            raise SystemExit(message) from exc


def main():
    parser = argparse.ArgumentParser(description="Wake the controlled autoSOC heart.")
    parser.add_argument("--model", default="artifacts/aisoc_model.joblib", help="Saved AISOC .joblib brain.")
    parser.add_argument("--csv", default="cybersecurity.csv", help="CSV to classify and respond to.")
    parser.add_argument("--output", default="artifacts/autosoc_predictions.csv", help="Where predictions are written.")
    parser.add_argument("--work-dir", default="artifacts/autosoc", help="Where tickets and heart state are written.")
    parser.add_argument("--rows", type=int, default=25, help="Only read the first N rows. Use 0 for all rows.")
    parser.add_argument("--max-actions", type=int, default=10, help="Maximum actionable rows to process.")
    parser.add_argument("--alert-dir", default="artifacts/alerts", help="Where human alert JSON files are written.")
    parser.add_argument("--alert-config", default=None, help="Notification config file. Defaults to artifacts/notify_config.json.")
    parser.add_argument("--alert-min-severity", default="high", help="Minimum severity to alert: low, medium, high, critical.")
    parser.add_argument("--no-alert-console", action="store_true", help="Do not print human alerts to the terminal.")
    parser.add_argument("--listen", action="store_true", help="Heartbeat mode: listen for new dangerous CSV rows and alert.")
    parser.add_argument("--listen-interval", type=int, default=10, help="Seconds between heartbeat CSV checks.")
    parser.add_argument("--listen-state", default="artifacts/autosoc_listener_state.json", help="Where listener cursor state is stored.")
    parser.add_argument("--label-column", default="Label", help="Label column for raw CSV alert listening.")
    parser.add_argument("--from-start", action="store_true", help="Listen from row 0 instead of tailing new rows.")
    parser.add_argument("--once", action="store_true", help="Run one listener heartbeat cycle and exit.")
    parser.add_argument("--packets", action="store_true", help="Read real packets, build flow features, and alert on scary flows.")
    parser.add_argument("--pcap", default=None, help="Read packets from a pcap file instead of sniffing live traffic.")
    parser.add_argument("--interface", default=None, help="Live network interface to sniff, such as eth0 or wlan0.")
    parser.add_argument("--packet-duration", type=int, default=30, help="Live packet capture window in seconds.")
    parser.add_argument("--packet-count", type=int, default=0, help="Live packet count limit. 0 means unlimited until timeout.")
    parser.add_argument("--packet-filter", default="ip and (tcp or udp or icmp)", help="BPF filter for live capture.")
    parser.add_argument("--packet-watch", action="store_true", help="Continuously capture and classify packet windows.")
    parser.add_argument("--packet-flow-output", default="artifacts/packet_flows.csv", help="Where packet flow features are written.")
    parser.add_argument("--packet-prediction-output", default="artifacts/packet_predictions.csv", help="Where packet predictions are written.")
    parser.add_argument("--execute", action="store_true", help="Ask before running allowlisted Linux commands.")
    parser.add_argument("--yes", action="store_true", help="Skip the EXECUTE prompt. Use only in a lab.")
    parser.add_argument(
        "--allow-containment",
        action="store_true",
        help="Allow approved iptables containment when a source IP exists.",
    )
    args = parser.parse_args()

    rows = None if args.rows == 0 else args.rows
    notifier = build_notifier_from_env(
        min_severity=args.alert_min_severity,
        alert_dir=args.alert_dir,
        console=not args.no_alert_console,
        config_path=args.alert_config,
    )

    if args.packets or args.pcap or args.interface or args.packet_watch:
        from packet_eyes import PacketSOC

        packet_soc = PacketSOC(
            model_path=args.model,
            notifier=notifier,
            prediction_output=args.packet_prediction_output,
            flow_output=args.packet_flow_output,
            max_alerts=args.max_actions,
        )
        if args.pcap:
            packet_soc.inspect_pcap(args.pcap)
        elif args.packet_watch:
            packet_soc.watch_interface(
                interface=args.interface,
                window=args.packet_duration,
                packet_filter=args.packet_filter,
            )
        else:
            packet_soc.inspect_interface(
                interface=args.interface,
                duration=args.packet_duration,
                count=args.packet_count,
                packet_filter=args.packet_filter,
            )
        return

    if args.listen:
        watch_csv_for_alerts(
            args.csv,
            notifier,
            label_column=args.label_column,
            interval=args.listen_interval,
            state_file=args.listen_state,
            max_alerts=args.max_actions,
            from_start=args.from_start,
            once=args.once,
        )
        return

    heart = AutoSOCHeart(
        model_path=args.model,
        work_dir=args.work_dir,
        execute=args.execute,
        assume_yes=args.yes,
        allow_containment=args.allow_containment,
        max_actions=args.max_actions,
        notifier=notifier,
    )
    heart.wake(args.csv, output_path=args.output, rows=rows)


if __name__ == "__main__":
    main()
