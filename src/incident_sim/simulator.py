"""Deterministic, seedable incident simulator.

>>> from incident_sim import IncidentSimulator
>>> sim = IncidentSimulator("bot_attack", seed=7)
>>> sim.alert()["name"]
'Traffic spike + elevated 403/429'
>>> sim.metrics(["requests"], last_minutes=5)["requests"][-1] > 2000
True
"""
from __future__ import annotations

import random
import re
import zlib
from datetime import datetime, timedelta, timezone

from .scenarios import BASELINE, PROBES, SERVICES, Scenario, get_scenario


class DataSourceUnavailable(RuntimeError):
    """Raised when a data source has been configured to fail (fault injection)."""


class IncidentSimulator:
    """Generates metrics, logs and context for one incident scenario.

    Parameters
    ----------
    scenario_id: one of ``incident_sim.SCENARIOS``.
    seed: random seed; the same seed always yields identical data.
    window_minutes: history length returned by :meth:`metrics`.
    incident_age_minutes: how long ago the incident started.
    fail_sources: data sources that raise :class:`DataSourceUnavailable`
        (``"metrics"``, ``"logs"``, ``"events"``, ``"vendor_status"``, ``"host"``) to test
        how an agent degrades when a tool is down.
    start_time: wall-clock time of the last sample (defaults to a fixed date
        so that output is reproducible).
    """

    def __init__(self, scenario_id: str, seed: int = 42, window_minutes: int = 60,
                 incident_age_minutes: int = 20, fail_sources: set[str] | None = None,
                 start_time: datetime | None = None) -> None:
        self.scenario: Scenario = get_scenario(scenario_id)
        self.seed = seed
        self.window = window_minutes
        self.age = min(incident_age_minutes, window_minutes)
        self.fail_sources = set(fail_sources or ())
        self.now = start_time or datetime(2026, 10, 31, 18, 0, tzinfo=timezone.utc)
        self.applied_actions: list[str] = []
        self._series = self._generate_series()

    # ------------------------------------------------------------------ helpers
    def _check(self, source: str) -> None:
        if source in self.fail_sources:
            raise DataSourceUnavailable(f"{source} API unavailable (simulated outage)")

    def _rng(self, salt: str) -> random.Random:
        return random.Random(f"{self.seed}:{self.scenario.id}:{salt}")

    def _generate_series(self) -> dict[str, list[float]]:
        rng = self._rng("metrics")
        series: dict[str, list[float]] = {}
        start_idx = self.window - self.age
        for name, base in BASELINE.items():
            effect = self.scenario.metric_effects.get(name)
            values = []
            for i in range(self.window):
                v = base
                if effect is not None and i >= start_idx:
                    ramp = min(1.0, (i - start_idx + 1) / 3)  # 3-minute ramp
                    v = base + (effect(base) - base) * ramp
                noise = 1 + rng.uniform(-0.05, 0.05)
                v = v * noise
                if name.endswith("_pct"):
                    v = min(v, 100.0)
                if name == "cache_hit_ratio":
                    v = min(round(v, 3), 0.99)
                else:
                    v = round(v, 1)
                values.append(v)
            series[name] = values
        # keep derived metrics consistent
        for i in range(self.window):
            series["login_success"][i] = min(series["login_success"][i], series["login_attempts"][i])
            series["checkout_success"][i] = min(series["checkout_success"][i], series["checkout_attempts"][i])
        return series

    def _ts(self, minute_index: int) -> str:
        t = self.now - timedelta(minutes=self.window - 1 - minute_index)
        return t.isoformat().replace("+00:00", "Z")

    # --------------------------------------------------------------- public API
    def alert(self) -> dict:
        """The alert that would be sent by monitoring (input to n8n / agents)."""
        a = dict(self.scenario.alert)
        a.update({"fired_at": self._ts(self.window - self.age + 2),
                  "incident_id": f"INC-{self.seed:04d}-{zlib.crc32(self.scenario.id.encode()) % 1000:03d}"})
        return a

    def metric_names(self) -> list[str]:
        return list(BASELINE)

    def metrics(self, names: list[str] | None = None, last_minutes: int = 30) -> dict[str, list[float]]:
        """Per-minute metric series (oldest first)."""
        self._check("metrics")
        names = names or list(BASELINE)
        unknown = [n for n in names if n not in self._series]
        if unknown:
            raise KeyError(f"Unknown metrics {unknown}. Known: {list(BASELINE)}")
        n = max(1, min(last_minutes, self.window))
        return {k: self._series[k][-n:] for k in names}

    def metric_summary(self) -> dict[str, dict[str, float]]:
        """Baseline (before incident) vs. current (last 5 min) average per metric."""
        self._check("metrics")
        out = {}
        split = self.window - self.age
        for k, vals in self._series.items():
            before = vals[:split] or vals
            after = vals[-5:]
            b = sum(before) / len(before)
            a = sum(after) / len(after)
            out[k] = {"baseline": round(b, 3), "current": round(a, 3),
                      "change_pct": round((a - b) / b * 100, 1) if b else 0.0}
        return out

    def logs(self, source: str | None = None, contains: str | None = None, limit: int = 50) -> list[dict]:
        """Synthetic log lines from the incident window (newest last)."""
        self._check("logs")
        rng = self._rng(f"logs:{source}:{contains}")
        rows = []
        start_idx = self.window - self.age
        for i in range(max(start_idx, self.window - 10), self.window):
            for src, tmpl, per_min in self.scenario.log_templates:
                if source and src != source:
                    continue
                for _ in range(max(1, per_min // 5)):
                    msg = tmpl.format(oct=rng.choice([7, 13, 21, 42, 77, 101]), n=rng.randint(10000, 99999))
                    rows.append({"ts": self._ts(i), "source": src, "message": msg})
        # background noise lines so the agent must filter
        noise = [("nginx_access", '192.0.2.{oct} "GET /catalog/product/view/id/{n} HTTP/2" 200'),
                 ("magento_system", "main.INFO: Cron job indexer_reindex_all_invalid finished")]
        for i in range(self.window - 10, self.window):
            src, tmpl = noise[i % 2]
            if source and src != source:
                continue
            rows.append({"ts": self._ts(i), "source": src,
                         "message": tmpl.format(oct=rng.randint(1, 254), n=rng.randint(1, 5000))})
        if contains:
            pat = re.compile(re.escape(contains), re.IGNORECASE)
            rows = [r for r in rows if pat.search(r["message"])]
        rows.sort(key=lambda r: r["ts"])
        return rows[-limit:]

    def log_sources(self) -> list[str]:
        return sorted({s for s, _, _ in self.scenario.log_templates} | {"nginx_access", "magento_system"})

    def events(self) -> list[dict]:
        """Deploys, campaigns, alarms and inventory facts around the incident."""
        self._check("events")
        out = []
        for e in self.scenario.events:
            idx = self.window - self.age + e["minute"]
            out.append({"ts": self._ts(max(0, min(idx, self.window - 1))), "type": e["type"], "detail": e["detail"]})
        out.append({"ts": self._ts(5), "type": "deploy", "detail": "Routine theme CSS tweak deployed (static content deployed)"})
        return sorted(out, key=lambda e: e["ts"])

    def vendor_status(self, vendor: str) -> dict:
        """Status of a third-party provider as its public status page would report."""
        self._check("vendor_status")
        status = self.scenario.vendor_status.get(vendor.lower())
        if status is None:
            raise KeyError(f"Unknown vendor '{vendor}'")
        return {"vendor": vendor.lower(), "status": status, "source": "simulated"}

    def host_state(self) -> dict:
        """Service states, local HTTP probes and host facts (what an on-server collector would report)."""
        self._check("host")
        sc = self.scenario
        services = {u: sc.services.get(u, "active") for u in SERVICES}
        probes = [{"name": n, "status": sc.probes.get(n, ok), "ms": 900 if sc.probes.get(n, ok) >= 500 else 120}
                  for n, ok in PROBES.items()]
        state = {"static_dir_present": True, "magento_cron_runs_5min": 5, "mail_queue": 0,
                 "nginx_config_newer_than_master": False, "valkey_reachable": True, **sc.state}
        if self._fixed():
            services = {u: "active" for u in SERVICES}
            probes = [{"name": n, "status": ok, "ms": 120} for n, ok in PROBES.items()]
            state = {"static_dir_present": True, "magento_cron_runs_5min": 5, "mail_queue": 0,
                     "nginx_config_newer_than_master": False, "valkey_reachable": True}
        return {"services": services, "probes": probes, "state": state}

    def _fixed(self) -> bool:
        return bool(set(self.applied_actions) & self.scenario.truth.fixing_actions)

    # ---------------------------------------------------------- remediation sim
    def apply_actions(self, action_ids: list[str]) -> dict:
        """Simulate executing remediation actions (never touches real systems).

        Returns the post-remediation health check used by the verifier.
        """
        truth = self.scenario.truth
        # earlier fixes stay in place; earlier harmful actions are assumed rolled back
        applied = set(action_ids) | (set(self.applied_actions) & truth.fixing_actions)
        self.applied_actions.extend(action_ids)
        fixed = bool(applied & truth.fixing_actions)
        harmful = sorted(applied & truth.harmful_actions)
        summary = self.metric_summary()
        post = {k: v["baseline"] if fixed else v["current"] for k, v in summary.items()}
        if harmful:
            # harmful actions hurt revenue / customers
            post["checkout_success"] = round(post["checkout_success"] * 0.4, 2)
            post["login_success"] = round(post["login_success"] * 0.6, 2)
        return {"resolved": fixed and not harmful, "fixed_root_cause": fixed,
                "harmful_actions": harmful, "post_metrics": post}

    def ground_truth(self) -> dict:
        t = self.scenario.truth
        return {"root_cause": t.root_cause, "fixing_actions": sorted(t.fixing_actions),
                "harmful_actions": sorted(t.harmful_actions), "summary": t.summary}
