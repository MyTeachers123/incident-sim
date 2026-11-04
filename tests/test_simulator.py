import pytest

from incident_sim import SCENARIOS, DataSourceUnavailable, IncidentSimulator


@pytest.mark.parametrize("sid", list(SCENARIOS))
def test_every_scenario_generates_data(sid):
    sim = IncidentSimulator(sid, seed=1)
    assert sim.alert()["severity"] in {"low", "medium", "high", "critical"}
    assert len(sim.metrics(last_minutes=10)["requests"]) == 10
    assert sim.logs(limit=5)
    assert sim.ground_truth()["root_cause"] == sid


def test_deterministic():
    a = IncidentSimulator("bot_attack", seed=3).metrics()
    b = IncidentSimulator("bot_attack", seed=3).metrics()
    assert a == b


def test_fault_injection():
    sim = IncidentSimulator("bot_attack", fail_sources={"logs"})
    with pytest.raises(DataSourceUnavailable):
        sim.logs()
    assert sim.metrics(["requests"])  # other sources still work


def test_fix_and_harm():
    sim = IncidentSimulator("viral_promo_traffic")
    assert sim.apply_actions(["scale_out_web"])["resolved"]
    sim2 = IncidentSimulator("viral_promo_traffic")
    out = sim2.apply_actions(["scale_out_web", "cf_block_asn"])
    assert not out["resolved"] and out["harmful_actions"] == ["cf_block_asn"]


def test_same_symptom_different_cause():
    attack = IncidentSimulator("bot_attack").metric_summary()
    promo = IncidentSimulator("viral_promo_traffic").metric_summary()
    assert attack["requests"]["change_pct"] > 300 and promo["requests"]["change_pct"] > 300
    assert promo["unique_ips"]["change_pct"] > 5 * attack["unique_ips"]["change_pct"]
