# incident-sim

Synthetic, seedable e-commerce incident data for testing AI incident-response agents.

It simulates a Magento storefront behind Cloudflare on AWS with PayPal checkout, and produces
per-minute metrics, log lines, context events (deploys, marketing campaigns, alarms) and
third-party vendor status for six incident scenarios. Every scenario carries a ground truth
(root cause, fixing actions, harmful actions), so you can score an agent automatically.

All data is fake. IP addresses come from the RFC 5737 documentation ranges, e-mails use
`example.com`, and nothing is sampled from a real system.

## Install

```bash
pip install "git+https://github.com/MyTeachers123/incident-sim"
# or, from a clone
pip install -e .
```

No dependencies besides the Python standard library (Python 3.10+).

## Quick start

```python
from incident_sim import IncidentSimulator, list_scenarios

print(list_scenarios())
sim = IncidentSimulator("viral_promo_traffic", seed=7)

sim.alert()                          # alert as monitoring would send it
sim.metric_summary()["requests"]     # {'baseline': ..., 'current': ..., 'change_pct': ...}
sim.metrics(["requests", "unique_ips"], last_minutes=10)
sim.logs(source="cloudflare_firewall", contains="block", limit=20)
sim.events()                         # deploys, campaigns, alarms
sim.vendor_status("paypal")          # {'vendor': 'paypal', 'status': 'operational', ...}

# score a remediation plan (simulated, never touches real systems)
sim.apply_actions(["scale_out_web"])  # {'resolved': True, 'harmful_actions': [], ...}
sim.ground_truth()                    # for evaluation only - do not show to the agent
```

Command line:

```bash
incident-sim list
incident-sim dump bot_attack --seed 3 --logs 10
```

## Scenarios

| id | Symptom | Root cause | Trap |
|---|---|---|---|
| `bot_attack` | traffic x6, 403/429 spike, login attempts x55 | credential stuffing from two ASNs | scaling out just feeds the bots |
| `paypal_credential_expired` | checkout success ~12% | PayPal API credential expired (error 10002) | disabling PayPal loses sales |
| `paypal_outage` | checkout success ~15% | PayPal returns 503 / timeouts | rotating credentials does nothing |
| `redis_session_failure` | login success ~20%, 5xx on /customer | session Redis at maxmemory | `FLUSHALL` logs every customer out |
| `stale_static_content` | 404 on /static, broken layout | deploy skipped static-content:deploy | rolling back the database |
| `viral_promo_traffic` | traffic x6.5, 429 spike (same as attack!) | legitimate promo customers | blocking/challenging real buyers |

The two pairs `bot_attack`/`viral_promo_traffic` and `paypal_credential_expired`/`paypal_outage`
share the headline symptom but need opposite fixes, so an agent must gather evidence
(unique IPs, user agents, campaign events, vendor status, error codes) instead of pattern-matching the alert.

## API reference

`IncidentSimulator(scenario_id, seed=42, window_minutes=60, incident_age_minutes=20, fail_sources=None, start_time=None)`

| Method | Returns |
|---|---|
| `alert()` | dict: source, name, severity, service, fired_at, incident_id |
| `metric_names()` | list of metric names |
| `metrics(names=None, last_minutes=30)` | dict name -> list of per-minute values (oldest first) |
| `metric_summary()` | dict name -> {baseline, current, change_pct} |
| `logs(source=None, contains=None, limit=50)` | list of {ts, source, message} |
| `log_sources()` | list of log source names |
| `events()` | list of {ts, type, detail} |
| `vendor_status(vendor)` | {vendor, status, source}; vendors: cloudflare, paypal, aws |
| `apply_actions(action_ids)` | {resolved, fixed_root_cause, harmful_actions, post_metrics} |
| `ground_truth()` | {root_cause, fixing_actions, harmful_actions, summary} |

**Fault injection.** `fail_sources={"logs", "metrics", "events", "vendor_status"}` makes the matching
methods raise `DataSourceUnavailable`, so you can test graceful degradation.

Module-level: `list_scenarios()`, `get_scenario(id)`, `SCENARIOS`, `ROOT_CAUSES`, `BASELINE`.

## Adding a scenario

Create a `Scenario` in `scenarios.py` with metric effects (`_x(factor)` multiplies the baseline,
`_set(value)` replaces it), log templates (`{oct}` = random IP octet, `{n}` = random number), events,
vendor status and a `GroundTruth`, then call `_register(...)`.

## Tests

```bash
pip install -e . pytest
pytest -q
```

## Used by

[agents-capstone-incident-response](https://github.com/MyTeachers123/agents-capstone-incident-response): a
multi-agent incident-response system (LangGraph + human-in-the-loop) that uses incident-sim for its tests,
evaluation and demos.

## License

MIT
