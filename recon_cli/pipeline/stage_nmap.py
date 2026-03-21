from __future__ import annotations

import shlex
import xml.etree.ElementTree as ET

from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.stage_base import Stage, note_missing_tool
from recon_cli.tools.executor import CommandError


class NmapStage(Stage):
    name = "nmap_scan"
    requires = ["hostname"]
    provides = ["asset"]

    HIGH_RISK_PORTS = {
        21,
        22,
        23,
        25,
        53,
        110,
        111,
        135,
        139,
        143,
        389,
        445,
        465,
        512,
        513,
        514,
        873,
        1099,
        1433,
        1521,
        2049,
        2181,
        2375,
        2376,
        2483,
        2484,
        3306,
        3389,
        3632,
        4444,
        5432,
        5672,
        5900,
        5985,
        5986,
        6379,
        7001,
        7002,
        8080,
        8081,
        8443,
        9200,
        9300,
        11211,
        15672,
        27017,
    }

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_nmap", False))

    def execute(self, context: PipelineContext) -> None:
        executor = context.executor
        if not executor.available("nmap"):
            context.logger.warning("nmap not available; skipping nmap stage")
            note_missing_tool(context, "nmap")
            return
        hosts_path = context.record.paths.artifact("dedupe_hosts.txt")
        if not hosts_path.exists():
            context.logger.info("No hosts for nmap scan")
            return
        with hosts_path.open("r", encoding="utf-8") as handle:
            hosts = [line.strip() for line in handle if line.strip()]
        if not hosts:
            context.logger.info("No hosts for nmap scan")
            return
        runtime = context.runtime_config
        max_hosts = max(0, int(getattr(runtime, "nmap_max_hosts", 0)))
        if max_hosts:
            hosts = hosts[:max_hosts]
        if not hosts:
            context.logger.info("No hosts after nmap cap")
            return
        batch_size = max(1, int(getattr(runtime, "nmap_batch_size", 25)))
        top_ports = int(getattr(runtime, "nmap_top_ports", 0))
        ports = getattr(runtime, "nmap_ports", None)
        nmap_args = getattr(runtime, "nmap_args", None)
        nmap_scripts = getattr(runtime, "nmap_scripts", None)
        timeout = int(getattr(runtime, "nmap_timeout", runtime.tool_timeout))
        nmap_dir = context.record.paths.ensure_subdir("nmap")
        total_ports = 0
        total_services = 0
        findings_added = 0

        for idx in range(0, len(hosts), batch_size):
            batch = hosts[idx : idx + batch_size]
            if not batch:
                continue
            batch_file = nmap_dir / f"targets_{idx // batch_size + 1}.txt"
            xml_path = nmap_dir / f"scan_{idx // batch_size + 1}.xml"
            batch_file.write_text("\n".join(batch) + "\n", encoding="utf-8")
            cmd = ["nmap", "-sV", "-Pn", "-oX", str(xml_path), "-iL", str(batch_file)]
            if ports:
                cmd.extend(["-p", str(ports)])
            elif top_ports:
                cmd.extend(["--top-ports", str(top_ports)])

            if nmap_scripts:
                cmd.extend(["--script", str(nmap_scripts)])

            if nmap_args:
                forbidden = {
                    "--script",
                    "-iL",
                    "--interactive",
                    "--privileged",
                    "--unprivileged",
                    "-o",
                    "--stylesheet",
                }
                try:
                    args_list = shlex.split(str(nmap_args))
                    dangerous = [a for a in args_list if any(f in a for f in forbidden)]
                    if dangerous:
                        context.logger.warning(
                            "Dangerous nmap_args detected and stripped: %s", dangerous
                        )
                        args_list = [
                            a for a in args_list if not any(f in a for f in forbidden)
                        ]
                    cmd.extend(args_list)
                except ValueError:
                    context.logger.warning("Invalid nmap_args; ignoring: %s", nmap_args)

            try:
                executor.run(cmd, check=False, timeout=timeout)
            except CommandError:
                context.logger.warning(
                    "nmap failed for batch %s", idx // batch_size + 1
                )
                continue
            if not xml_path.exists():
                continue
            try:
                tree = ET.parse(xml_path)
            except Exception:
                continue
            root = tree.getroot()
            for host_node in root.findall("host"):
                status = host_node.find("status")
                if status is not None and status.get("state") != "up":
                    continue
                addr = None
                for address in host_node.findall("address"):
                    if address.get("addrtype") == "ipv4":
                        addr = address.get("addr")
                        break
                hostnames = [
                    hn.get("name")
                    for hn in host_node.findall("hostnames/hostname")
                    if hn.get("name")
                ]
                hostname = hostnames[0] if hostnames else addr
                for port_node in host_node.findall("ports/port"):
                    state = port_node.find("state")
                    if state is None or state.get("state") not in {
                        "open",
                        "open|filtered",
                    }:
                        continue
                    port_id = int(port_node.get("portid", "0"))
                    protocol = port_node.get("protocol") or "tcp"
                    service_node = port_node.find("service")
                    service_name = (
                        service_node.get("name") if service_node is not None else None
                    )
                    product = (
                        service_node.get("product")
                        if service_node is not None
                        else None
                    )
                    version = (
                        service_node.get("version")
                        if service_node is not None
                        else None
                    )
                    tags = {f"port:{port_id}", f"proto:{protocol}"}
                    if service_name:
                        tags.add(f"service:{service_name}")
                    if port_id in self.HIGH_RISK_PORTS:
                        tags.add("risk:exposed")
                    payload = {
                        "type": "service",
                        "source": "nmap",
                        "hostname": hostname,
                        "ip": addr,
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "tags": sorted(tags),
                        "score": 35 if port_id in self.HIGH_RISK_PORTS else 10,
                    }
                    if context.results.append(payload):
                        total_services += 1
                        total_ports += 1
                    if port_id in self.HIGH_RISK_PORTS:
                        finding = {
                            "type": "finding",
                            "source": "nmap",
                            "hostname": hostname,
                            "description": f"Potentially risky service exposed on port {port_id}",
                            "details": {
                                "port": port_id,
                                "protocol": protocol,
                                "service": service_name,
                                "product": product,
                                "version": version,
                                "ip": addr,
                            },
                            "tags": ["nmap", "exposure", f"port:{port_id}"],
                            "score": 55,
                            "priority": "medium",
                        }
                        if context.results.append(finding):
                            findings_added += 1

        stats = context.record.metadata.stats.setdefault("nmap", {})
        stats["hosts"] = len(hosts)
        stats["services"] = total_services
        stats["findings"] = findings_added
        context.manager.update_metadata(context.record)

        if getattr(runtime, "nmap_udp", False):
            udp_ports = int(getattr(runtime, "nmap_udp_top_ports", 200))
            udp_xml = nmap_dir / "scan_udp.xml"
            udp_targets = nmap_dir / "targets_udp.txt"
            udp_targets.write_text("\n".join(hosts) + "\n", encoding="utf-8")
            udp_cmd = [
                "nmap",
                "-sU",
                "-Pn",
                "-oX",
                str(udp_xml),
                "-iL",
                str(udp_targets),
                "--top-ports",
                str(udp_ports),
            ]
            if nmap_scripts:
                udp_cmd.extend(["--script", str(nmap_scripts)])
            if nmap_args:
                try:
                    args_list = shlex.split(str(nmap_args))
                    args_list = [
                        a for a in args_list if not any(f in a for f in forbidden)
                    ]
                    udp_cmd.extend(args_list)
                except ValueError:
                    pass
            try:
                executor.run(udp_cmd, check=False, timeout=timeout)
            except CommandError:
                context.logger.warning("nmap UDP scan failed")
                return
            if udp_xml.exists():
                try:
                    tree = ET.parse(udp_xml)
                except Exception:
                    return
                root = tree.getroot()
                udp_services = 0
                for host_node in root.findall("host"):
                    status = host_node.find("status")
                    if status is not None and status.get("state") != "up":
                        continue
                    addr = None
                    for address in host_node.findall("address"):
                        if address.get("addrtype") == "ipv4":
                            addr = address.get("addr")
                            break
                    hostnames = [
                        hn.get("name")
                        for hn in host_node.findall("hostnames/hostname")
                        if hn.get("name")
                    ]
                    hostname = hostnames[0] if hostnames else addr
                    for port_node in host_node.findall("ports/port"):
                        state = port_node.find("state")
                        if state is None or state.get("state") not in {
                            "open",
                            "open|filtered",
                        }:
                            continue
                        port_id = int(port_node.get("portid", "0"))
                        service_node = port_node.find("service")
                        service_name = (
                            service_node.get("name")
                            if service_node is not None
                            else None
                        )
                        payload = {
                            "type": "service",
                            "source": "nmap-udp",
                            "hostname": hostname,
                            "ip": addr,
                            "port": port_id,
                            "protocol": "udp",
                            "service": service_name,
                            "tags": ["udp", f"port:{port_id}"],
                            "score": 25,
                        }
                        if context.results.append(payload):
                            udp_services += 1
                if udp_services:
                    stats = context.record.metadata.stats.setdefault("nmap", {})
                    stats["udp_services"] = udp_services
                    context.manager.update_metadata(context.record)
