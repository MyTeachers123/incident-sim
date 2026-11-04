"""incident-sim: synthetic e-commerce incident data for testing AI agents."""
from .scenarios import BASELINE, ROOT_CAUSES, SCENARIOS, get_scenario, list_scenarios
from .simulator import DataSourceUnavailable, IncidentSimulator

__all__ = ["BASELINE", "ROOT_CAUSES", "SCENARIOS", "DataSourceUnavailable",
           "IncidentSimulator", "get_scenario", "list_scenarios"]
__version__ = "0.1.0"
