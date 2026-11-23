# backend/app/services/network_monitor.py
"""Continuous Network Monitoring Service & Job Scheduler
Orchestrates background sweeps, prevents duplicate/overlapping jobs, enforces
scope boundaries, handles timeouts and safe recovery, and logs cryptographic audit trails.
"""

import asyncio
import json
import logging
import sqlite3
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from ..db.database import connect, now_iso
from ..core.audit import record_audit_entry
from ..engines.network_scanner import (
    expand_scope_to_target_ips, probe_host, compare_with_baseline,
    validate_ip_in_approved_scope, EmergencyStopTriggered, ScopeViolationError
)

logger = logging.getLogger("agentshield.network_monitor")

class NetworkMonitoringService:
    def __init__(self):
        self._running_task: Optional[asyncio.Task] = None
        self._current_scan_task: Optional[asyncio.Task] = None
        self._scan_lock = asyncio.Lock()
        self._stop_event = asyncio.Event()
        self._is_active = False
        self._emergency_stop_cached = False
        self._initial_delay_seconds = 30

    def is_service_active(self) -> bool:
        return self._is_active and (self._running_task is not None and not self._running_task.done())

    def start_background_service(self):
        """Starts the persistent background monitoring scheduler loop safely (idempotent)."""
        if self._running_task is not None and not self._running_task.done():
            logger.debug("Network monitoring scheduler is already running; skipping duplicate start.")
            return

        self._stop_event.clear()
        self._is_active = True

        # Decouple backend startup from overdue scans: advance overdue next_scan_at
        try:
            with connect() as db:
                row = db.execute("SELECT emergency_stop, scan_interval_seconds, next_scan_at FROM network_monitoring_config LIMIT 1").fetchone()
                if row:
                    self._emergency_stop_cached = bool(row["emergency_stop"] == 1)
                    scan_int = row["scan_interval_seconds"] or 60
                    now_dt = datetime.now(timezone.utc)
                    next_iso = row["next_scan_at"]
                    is_overdue = True
                    if next_iso:
                        try:
                            is_overdue = datetime.fromisoformat(next_iso) <= now_dt
                        except Exception:
                            is_overdue = True
                    if is_overdue:
                        safe_next = (now_dt + timedelta(seconds=max(60, scan_int))).isoformat()
                        db.execute("UPDATE network_monitoring_config SET next_scan_at = ? WHERE id = 1", (safe_next,))
        except Exception as e:
            logger.debug(f"Initial network config sync note: {e}")

        self._running_task = asyncio.create_task(self._scheduler_loop(), name="network_monitor_scheduler")
        logger.info("Continuous Network Monitoring Service started.")

    async def stop_background_service(self):
        """Stops the persistent background scheduler loop cleanly and cancels running scans."""
        self._is_active = False
        self._stop_event.set()
        if self._current_scan_task and not self._current_scan_task.done():
            self._current_scan_task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(self._current_scan_task), timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                pass
            self._current_scan_task = None

        if self._running_task and not self._running_task.done():
            self._running_task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(self._running_task), timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                pass
            self._running_task = None
        logger.info("Continuous Network Monitoring Service stopped.")

    def trigger_emergency_stop(self, actor: str = "admin", reason: str = "Operator manual emergency stop") -> Dict[str, Any]:
        """Global emergency stop: immediately cancels in-flight scan, updates DB flag,
        and records an immutable cryptographic audit record.
        """
        self._emergency_stop_cached = True
        if self._current_scan_task and not self._current_scan_task.done():
            self._current_scan_task.cancel()

        now = now_iso()
        with connect() as db:
            db.execute("""
                UPDATE network_monitoring_config
                SET emergency_stop = 1, is_paused = 1, updated_at = ?
            """, (now,))
            
            # Mark any active RUNNING jobs as CANCELLED
            db.execute("""
                UPDATE scan_jobs
                SET status = 'CANCELLED', error_message = ?, completed_at = ?
                WHERE status = 'RUNNING'
            """, (f"Global Emergency Stop activated by {actor}: {reason}", now))

            # Record audit entry
            record_audit_entry(
                db,
                actor=actor,
                action="NETWORK_EMERGENCY_STOP_ACTIVATED",
                resource="network_monitoring",
                details={"reason": reason, "timestamp": now}
            )

        logger.warning(f"GLOBAL EMERGENCY STOP TRIGGERED by {actor}: {reason}")
        return {
            "status": "EMERGENCY_STOP_ACTIVATED",
            "message": "Continuous network scanning halted immediately. All probes aborted.",
            "timestamp": now
        }

    def reset_emergency_stop(self, actor: str = "admin") -> Dict[str, Any]:
        """Resets the global emergency stop flag, permitting scans to be scheduled again."""
        self._emergency_stop_cached = False
        now = now_iso()
        with connect() as db:
            db.execute("""
                UPDATE network_monitoring_config
                SET emergency_stop = 0, is_paused = 0, updated_at = ?
            """, (now,))

            record_audit_entry(
                db,
                actor=actor,
                action="NETWORK_EMERGENCY_STOP_RESET",
                resource="network_monitoring",
                details={"reset_by": actor, "timestamp": now}
            )

        logger.info(f"Global Emergency Stop reset by {actor}.")
        return {
            "status": "EMERGENCY_STOP_RESET",
            "message": "Emergency stop cleared. Continuous monitoring ready for activation.",
            "timestamp": now
        }

    def get_monitoring_status(self) -> Dict[str, Any]:
        """Retrieves comprehensive monitoring state, active config, scan statistics, and schedule."""
        with connect() as db:
            cfg = db.execute("SELECT * FROM network_monitoring_config ORDER BY id ASC LIMIT 1").fetchone()
            if not cfg:
                return {"status": "NOT_CONFIGURED", "service_enabled": 0}

            cfg_d = dict(cfg)
            scopes = db.execute("SELECT cidr_or_ip, name FROM approved_scan_scopes WHERE is_approved = 1").fetchall()
            exclusions = db.execute("SELECT ip_address, reason FROM network_exclusions").fetchall()
            last_job = db.execute("SELECT * FROM scan_jobs ORDER BY started_at DESC LIMIT 1").fetchone()
            active_job = db.execute("SELECT * FROM scan_jobs WHERE status = 'RUNNING' LIMIT 1").fetchone()

            total_assets = db.execute("SELECT COUNT(*) FROM network_assets").fetchone()[0]
            reachable_assets = db.execute("SELECT COUNT(*) FROM network_assets WHERE status = 'REACHABLE'").fetchone()[0]
            total_open_services = db.execute("SELECT COUNT(*) FROM service_observations WHERE state = 'OPEN'").fetchone()[0]
            unresolved_alerts = db.execute("SELECT COUNT(*) FROM network_security_alerts WHERE status = 'OPEN'").fetchone()[0]

            now_dt = datetime.now(timezone.utc)
            next_scan_dt_str = cfg_d.get("next_scan_at")
            seconds_until_next_scan = 0
            if next_scan_dt_str:
                try:
                    next_dt = datetime.fromisoformat(next_scan_dt_str)
                    seconds_until_next_scan = max(0, int((next_dt - now_dt).total_seconds()))
                except Exception:
                    seconds_until_next_scan = cfg_d.get("scan_interval_seconds", 60)

            state_label = "ACTIVE"
            if cfg_d["emergency_stop"] == 1:
                state_label = "EMERGENCY_STOP"
            elif cfg_d["is_paused"] == 1:
                state_label = "PAUSED"
            elif cfg_d["service_enabled"] == 0:
                state_label = "STOPPED"
            elif active_job or (self._current_scan_task and not self._current_scan_task.done()):
                state_label = "SCANNING"

            return {
                "state": state_label,
                "service_enabled": bool(cfg_d["service_enabled"]),
                "is_paused": bool(cfg_d["is_paused"]),
                "emergency_stop": bool(cfg_d["emergency_stop"]),
                "scan_interval_seconds": cfg_d["scan_interval_seconds"],
                "scan_duration_limit_seconds": cfg_d["scan_duration_limit_seconds"],
                "max_concurrency": cfg_d["max_concurrency"],
                "probe_timeout_seconds": cfg_d["probe_timeout_seconds"],
                "last_scan_at": cfg_d.get("last_scan_at"),
                "next_scan_at": cfg_d.get("next_scan_at"),
                "seconds_until_next_scan": seconds_until_next_scan,
                "approved_scopes_count": len(scopes),
                "exclusions_count": len(exclusions),
                "total_assets_known": total_assets,
                "reachable_assets": reachable_assets,
                "total_open_services": total_open_services,
                "unresolved_alerts": unresolved_alerts,
                "current_job": dict(active_job) if active_job else None,
                "last_completed_job": dict(last_job) if last_job else None
            }

    async def execute_scan_cycle(self, triggered_by: str = "SCHEDULER") -> Dict[str, Any]:
        """Executes a single end-to-end authorized scan sweep with duplicate prevention,
        duration timeout limits, safe recovery, and baseline comparison.
        """
        # Duplicate Prevention: If lock is already held, reject or skip overlapping run
        if self._scan_lock.locked():
            logger.warning("Scan cycle already in progress. Skipping overlapping job execution.")
            return {
                "status": "SKIPPED",
                "message": "Scan job already running. Overlapping scans are strictly prohibited."
            }

        async with self._scan_lock:
            # 1. Read configuration & verify emergency stop / pause
            with connect() as db:
                cfg = db.execute("SELECT * FROM network_monitoring_config LIMIT 1").fetchone()
                if not cfg:
                    return {"status": "ERROR", "message": "Network monitoring configuration not found"}
                cfg = dict(cfg)

                if cfg["emergency_stop"] == 1:
                    return {"status": "BLOCKED", "message": "Cannot scan: Global emergency stop is engaged"}
                if cfg["is_paused"] == 1 and triggered_by == "SCHEDULER":
                    return {"status": "PAUSED", "message": "Continuous monitoring is currently paused"}
                if cfg["service_enabled"] == 0 and triggered_by == "SCHEDULER":
                    return {"status": "STOPPED", "message": "Continuous monitoring service is disabled"}

                # Load approved scopes and exclusions
                scope_rows = db.execute("SELECT cidr_or_ip FROM approved_scan_scopes WHERE is_approved = 1").fetchall()
                approved_cidrs = [r[0] for r in scope_rows]
                excl_rows = db.execute("SELECT ip_address FROM network_exclusions").fetchall()
                excluded_ips = [r[0] for r in excl_rows]

                # Load baseline assets & baseline services
                asset_rows = db.execute("SELECT ip_address, hostname, in_baseline, last_seen FROM network_assets").fetchall()
                baseline_assets = {r[0]: dict(r) for r in asset_rows}

                srv_rows = db.execute("SELECT ip_address, port FROM service_observations WHERE is_baseline = 1").fetchall()
                baseline_services: Dict[str, set] = {}
                for r in srv_rows:
                    baseline_services.setdefault(r[0], set()).add(r[1])

            if not approved_cidrs:
                logger.warning("No approved scan scopes configured. Skipping scan.")
                return {"status": "SKIPPED", "message": "No approved network scopes configured"}

            target_ips = expand_scope_to_target_ips(approved_cidrs, excluded_ips)
            if not target_ips:
                logger.warning("No eligible target IPs found after applying exclusions.")
                return {"status": "SKIPPED", "message": "All IPs within approved scope are excluded"}

            # Parse ports and concurrency
            target_ports = json.loads(cfg.get("target_ports_json") or "[80, 443, 8000]")
            concurrency = max(1, min(cfg.get("max_concurrency", 10), 50))
            timeout_sec = float(cfg.get("probe_timeout_seconds", 1.0))
            duration_limit = int(cfg.get("scan_duration_limit_seconds", 120))

            # 2. Register scan job in database
            job_id = f"scan-{uuid.uuid4().hex[:10]}"
            now = now_iso()
            with connect() as db:
                db.execute("""
                    INSERT INTO scan_jobs (
                        id, status, triggered_by, target_scope_json, hosts_scanned,
                        hosts_up, ports_found, changes_detected, alerts_generated,
                        error_message, started_at
                    ) VALUES (?, 'RUNNING', ?, ?, ?, 0, 0, 0, 0, NULL, ?)
                """, (job_id, triggered_by, json.dumps(approved_cidrs), len(target_ips), now))

                record_audit_entry(
                    db,
                    actor=triggered_by,
                    action="NETWORK_SCAN_JOB_STARTED",
                    resource=f"scan_jobs:{job_id}",
                    details={"target_hosts_count": len(target_ips), "scopes": approved_cidrs}
                )

            # 3. Execute scan with bounded concurrency and strict duration limits
            semaphore = asyncio.Semaphore(concurrency)
            scan_results: List[Dict[str, Any]] = []

            def _check_emergency_stop() -> bool:
                # Fast in-memory check to avoid thousands of parallel SQLite queries
                if self._emergency_stop_cached:
                    return True
                return False

            async def _run_sweep():
                results = []
                # Chunk target IPs to avoid overflowing OS socket handles or choking the event loop
                chunk_size = max(5, concurrency)
                for i in range(0, len(target_ips), chunk_size):
                    if _check_emergency_stop() or self._stop_event.is_set():
                        raise EmergencyStopTriggered("Scan cancelled: Global emergency stop engaged")
                    chunk = target_ips[i:i + chunk_size]
                    tasks = [
                        probe_host(
                            ip,
                            target_ports=target_ports,
                            timeout_seconds=timeout_sec,
                            semaphore=semaphore,
                            emergency_stop_check=_check_emergency_stop
                        )
                        for ip in chunk
                    ]
                    chunk_res = await asyncio.gather(*tasks, return_exceptions=True)
                    for r in chunk_res:
                        if isinstance(r, Exception):
                            if isinstance(r, (EmergencyStopTriggered, asyncio.CancelledError)):
                                raise r
                            logger.debug(f"Host probe error: {r}")
                        elif r:
                            results.append(r)
                return results

            try:
                self._current_scan_task = asyncio.create_task(_run_sweep())
                scan_results = await asyncio.wait_for(self._current_scan_task, timeout=duration_limit)
            except asyncio.TimeoutError:
                err_msg = f"Scan duration exceeded limit of {duration_limit} seconds. Terminated safely."
                logger.error(err_msg)
                now_failed = now_iso()
                next_scan_time = (datetime.now(timezone.utc) + timedelta(seconds=cfg.get("scan_interval_seconds", 60))).isoformat()
                with connect() as db:
                    db.execute("""
                        UPDATE scan_jobs
                        SET status = 'FAILED', error_message = ?, completed_at = ?
                        WHERE id = ?
                    """, (err_msg, now_failed, job_id))
                    # Critical: Advance next_scan_at so it doesn't immediately re-trigger in a tight loop
                    db.execute("""
                        UPDATE network_monitoring_config
                        SET last_scan_at = ?, next_scan_at = ?, updated_at = ?
                    """, (now_failed, next_scan_time, now_failed))
                    record_audit_entry(
                        db,
                        actor=triggered_by,
                        action="NETWORK_SCAN_TIMEOUT_ERROR",
                        resource=f"scan_jobs:{job_id}",
                        details={"error": err_msg, "next_scan_at": next_scan_time}
                    )
                return {"status": "FAILED", "job_id": job_id, "error": err_msg}
            except (asyncio.CancelledError, EmergencyStopTriggered):
                err_msg = "Scan cancelled immediately due to emergency stop or operator shutdown."
                logger.warning(err_msg)
                now_cancelled = now_iso()
                next_scan_time = (datetime.now(timezone.utc) + timedelta(seconds=cfg.get("scan_interval_seconds", 60))).isoformat()
                with connect() as db:
                    db.execute("""
                        UPDATE scan_jobs
                        SET status = 'CANCELLED', error_message = ?, completed_at = ?
                        WHERE id = ?
                    """, (err_msg, now_cancelled, job_id))
                    db.execute("""
                        UPDATE network_monitoring_config
                        SET last_scan_at = ?, next_scan_at = ?, updated_at = ?
                    """, (now_cancelled, next_scan_time, now_cancelled))
                return {"status": "CANCELLED", "job_id": job_id, "error": err_msg}
            except Exception as e:
                err_msg = f"Unexpected scanner failure: {str(e)}"
                logger.exception(err_msg)
                now_failed = now_iso()
                next_scan_time = (datetime.now(timezone.utc) + timedelta(seconds=cfg.get("scan_interval_seconds", 60))).isoformat()
                with connect() as db:
                    db.execute("""
                        UPDATE scan_jobs
                        SET status = 'FAILED', error_message = ?, completed_at = ?
                        WHERE id = ?
                    """, (err_msg, now_failed, job_id))
                    db.execute("""
                        UPDATE network_monitoring_config
                        SET last_scan_at = ?, next_scan_at = ?, updated_at = ?
                    """, (now_failed, next_scan_time, now_failed))
                    record_audit_entry(
                        db,
                        actor=triggered_by,
                        action="NETWORK_SCAN_FAILURE",
                        resource=f"scan_jobs:{job_id}",
                        details={"error": err_msg, "next_scan_at": next_scan_time}
                    )
                return {"status": "FAILED", "job_id": job_id, "error": err_msg}
            finally:
                self._current_scan_task = None

            # 4. Compare with Baseline & Generate Security Alerts
            alerts, asset_updates, changes_count = compare_with_baseline(
                scan_results,
                baseline_assets,
                baseline_services
            )

            # 5. Persist scan results, update inventory & log completed audit record
            now_completed = now_iso()
            hosts_up_count = sum(1 for a in asset_updates if a["status"] == "REACHABLE")
            ports_found_count = sum(len(a.get("open_ports", [])) for a in asset_updates)

            with connect() as db:
                # Update assets
                for asset in asset_updates:
                    db.execute("""
                        INSERT INTO network_assets (
                            id, ip_address, hostname, mac_address, status, in_baseline,
                            first_seen, last_seen, last_scan_job_id, latency_ms, metadata_json
                        ) VALUES (?, ?, ?, '00:00:00:00:00:00', ?, ?, ?, ?, ?, ?, '{}')
                        ON CONFLICT(ip_address) DO UPDATE SET
                            hostname = excluded.hostname,
                            status = excluded.status,
                            last_seen = excluded.last_seen,
                            last_scan_job_id = excluded.last_scan_job_id,
                            latency_ms = excluded.latency_ms
                    """, (
                        f"net-{asset['ip_address'].replace('.', '-')}",
                        asset["ip_address"],
                        asset["hostname"],
                        asset["status"],
                        asset["in_baseline"],
                        now_completed,
                        now_completed,
                        job_id,
                        asset.get("latency_ms")
                    ))

                    # Update observed services
                    for p in asset.get("open_ports", []):
                        db.execute("""
                            INSERT INTO service_observations (
                                asset_id, ip_address, port, protocol, service_name,
                                banner, state, is_baseline, first_observed, last_observed, last_scan_job_id
                            ) VALUES (?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?)
                        """, (
                            f"net-{asset['ip_address'].replace('.', '-')}",
                            asset["ip_address"],
                            p["port"],
                            p["protocol"],
                            p["service_name"],
                            p.get("banner", ""),
                            1 if p["port"] in baseline_services.get(asset["ip_address"], set()) else 0,
                            now_completed,
                            now_completed,
                            job_id
                        ))

                # Insert alerts
                for alt in alerts:
                    db.execute("""
                        INSERT INTO network_security_alerts (
                            scan_job_id, alert_type, severity, title, observed_fact,
                            suspected_threat, target_ip, target_port, evidence_json, status, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?)
                    """, (
                        job_id,
                        alt["alert_type"],
                        alt["severity"],
                        alt["title"],
                        alt["observed_fact"],
                        alt["suspected_threat"],
                        alt["target_ip"],
                        alt.get("target_port"),
                        json.dumps(alt.get("evidence_json", {})),
                        now_completed
                    ))

                # Update scan job completion
                db.execute("""
                    UPDATE scan_jobs
                    SET status = 'COMPLETED',
                        hosts_scanned = ?,
                        hosts_up = ?,
                        ports_found = ?,
                        changes_detected = ?,
                        alerts_generated = ?,
                        completed_at = ?
                    WHERE id = ?
                """, (
                    len(target_ips),
                    hosts_up_count,
                    ports_found_count,
                    changes_count,
                    len(alerts),
                    now_completed,
                    job_id
                ))

                # Update config timestamps
                next_scan_time = (datetime.now(timezone.utc) + timedelta(seconds=cfg.get("scan_interval_seconds", 60))).isoformat()
                db.execute("""
                    UPDATE network_monitoring_config
                    SET last_scan_at = ?, next_scan_at = ?, updated_at = ?
                """, (now_completed, next_scan_time, now_completed))

                # Record completion in cryptographic ledger
                record_audit_entry(
                    db,
                    actor=triggered_by,
                    action="NETWORK_SCAN_JOB_COMPLETED",
                    resource=f"scan_jobs:{job_id}",
                    details={
                        "hosts_scanned": len(target_ips),
                        "hosts_up": hosts_up_count,
                        "ports_found": ports_found_count,
                        "changes_detected": changes_count,
                        "alerts_generated": len(alerts)
                    }
                )

            logger.info(f"Scan cycle {job_id} COMPLETED: {hosts_up_count}/{len(target_ips)} hosts reachable, {ports_found_count} open ports, {len(alerts)} alerts.")
            return {
                "status": "COMPLETED",
                "job_id": job_id,
                "hosts_scanned": len(target_ips),
                "hosts_up": hosts_up_count,
                "ports_found": ports_found_count,
                "changes_detected": changes_count,
                "alerts_generated": len(alerts),
                "completed_at": now_completed
            }

    async def _scheduler_loop(self):
        """Persistent background scheduler loop that periodically wakes up,
        checks if scan interval has elapsed, and runs the scan cycle without blocking.
        """
        # Initial startup grace period (30s) to let ASGI finish binding and health probes pass cleanly
        try:
            for _ in range(self._initial_delay_seconds):
                if self._stop_event.is_set():
                    return
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            return

        while not self._stop_event.is_set():
            try:
                # Check DB config for next scan eligibility
                should_scan = False
                with connect() as db:
                    cfg = db.execute("SELECT * FROM network_monitoring_config LIMIT 1").fetchone()
                    if cfg:
                        cfg_d = dict(cfg)
                        self._emergency_stop_cached = bool(cfg_d.get("emergency_stop") == 1)
                        if cfg_d["service_enabled"] == 1 and cfg_d["is_paused"] == 0 and not self._emergency_stop_cached:
                            next_scan_iso = cfg_d.get("next_scan_at")
                            if not next_scan_iso:
                                should_scan = True
                            else:
                                try:
                                    next_dt = datetime.fromisoformat(next_scan_iso)
                                    if datetime.now(timezone.utc) >= next_dt:
                                        should_scan = True
                                except Exception:
                                    should_scan = True

                if should_scan and not self._scan_lock.locked():
                    await self.execute_scan_cycle(triggered_by="SCHEDULER")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in network monitor scheduler loop: {e}", exc_info=True)

            # Sleep 5 seconds before next evaluation tick
            try:
                for _ in range(5):
                    if self._stop_event.is_set():
                        break
                    await asyncio.sleep(1)
            except asyncio.CancelledError:
                break


# Global singleton instance of the Network Monitoring Service
network_monitoring_service = NetworkMonitoringService()
