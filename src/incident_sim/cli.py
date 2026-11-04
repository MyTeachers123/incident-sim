"""Command line: ``incident-sim list`` / ``incident-sim dump bot_attack --seed 3``."""
from __future__ import annotations

import argparse
import json

from . import IncidentSimulator, list_scenarios


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="incident-sim")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list scenarios")
    d = sub.add_parser("dump", help="print alert, metric summary, logs and events as JSON")
    d.add_argument("scenario")
    d.add_argument("--seed", type=int, default=42)
    d.add_argument("--logs", type=int, default=20)
    a = p.parse_args(argv)
    if a.cmd == "list":
        print(json.dumps(list_scenarios(), indent=2))
        return
    sim = IncidentSimulator(a.scenario, seed=a.seed)
    print(json.dumps({"alert": sim.alert(), "metric_summary": sim.metric_summary(),
                      "logs": sim.logs(limit=a.logs), "events": sim.events()}, indent=2))


if __name__ == "__main__":
    main()
