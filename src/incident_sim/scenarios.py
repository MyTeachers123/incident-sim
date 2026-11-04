"""Scenario catalog for a synthetic Magento + Cloudflare + AWS + PayPal storefront.

Every scenario is fully synthetic. IP addresses come from the documentation
ranges reserved by RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
so no real host or customer is ever referenced.

A scenario describes:
  * how each metric deviates from the healthy baseline after ``start_minute``
  * which log lines the incident produces
  * contextual events (deploys, marketing campaigns, vendor status)
  * the ground truth (root cause + the remediation actions that fix it, and
    the actions that would make things worse) used for evaluation only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

# Healthy baseline per minute for a mid-size store.
BASELINE: dict[str, float] = {
    "requests": 800.0,
    "unique_ips": 420.0,
    "status_403": 4.0,
    "status_404": 6.0,
    "status_429": 1.0,
    "status_5xx": 2.0,
    "p95_ms": 420.0,
    "origin_cpu_pct": 35.0,
    "cache_hit_ratio": 0.82,
    "login_attempts": 30.0,
    "login_success": 27.0,
    "checkout_attempts": 12.0,
    "checkout_success": 11.0,
    "redis_memory_pct": 55.0,
}

ROOT_CAUSES = [
    "bot_attack",
    "paypal_credential_expired",
    "paypal_outage",
    "redis_session_failure",
    "stale_static_content",
    "viral_promo_traffic",
    "valkey_down",
    "opensearch_down",
    "php_fpm_down",
    "cron_stopped",
    "nginx_config_not_applied",
]

# Services of the reference stack (Ubuntu + nginx -> Varnish -> nginx -> PHP-FPM, MariaDB, OpenSearch, Valkey, RabbitMQ).
SERVICES = ["nginx", "varnish", "php8.5-fpm", "mariadb", "opensearch", "rabbitmq-server", "postfix", "cron",
            "valkey-server"]
# Local HTTP probes: name -> healthy status code.
PROBES = {"home": 200, "login_page": 200, "search": 200, "backend_health": 200, "static_css": 200}


@dataclass(frozen=True)
class GroundTruth:
    root_cause: str
    fixing_actions: frozenset[str]          # at least ONE of these must run
    harmful_actions: frozenset[str] = frozenset()  # any of these makes it worse
    summary: str = ""


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    alert: dict
    # metric name -> function(multiplier context) returning the incident value
    metric_effects: dict[str, Callable[[float], float]]
    log_templates: list[tuple[str, str, int]]   # (source, template, count per minute)
    events: list[dict] = field(default_factory=list)
    vendor_status: dict[str, str] = field(default_factory=dict)
    truth: GroundTruth | None = None
    services: dict[str, str] = field(default_factory=dict)   # overrides of "active"
    probes: dict[str, int] = field(default_factory=dict)     # overrides of PROBES
    state: dict = field(default_factory=dict)                # overrides of host state (cron runs, static dir, ...)


def _x(f: float) -> Callable[[float], float]:
    """Multiply the baseline value by ``f``."""
    return lambda base: base * f


def _set(v: float) -> Callable[[float], float]:
    return lambda base: v


SCENARIOS: dict[str, Scenario] = {}


def _register(s: Scenario) -> None:
    SCENARIOS[s.id] = s


_register(Scenario(
    id="bot_attack",
    title="Credential-stuffing bot attack on customer login",
    alert={"source": "cloudflare", "name": "Traffic spike + elevated 403/429",
           "severity": "high", "service": "storefront"},
    metric_effects={
        "requests": _x(6.0), "unique_ips": _x(1.08), "status_403": _x(90),
        "status_429": _x(400), "p95_ms": _x(3.2), "origin_cpu_pct": _set(93),
        "login_attempts": _x(55), "login_success": _x(0.9),
        "checkout_success": _x(0.75), "cache_hit_ratio": _x(0.6),
    },
    log_templates=[
        ("cloudflare_firewall", 'action=block rule=rate_limit_login ip=203.0.113.{oct} asn=AS64500 path=/customer/account/loginPost ua="python-requests/2.32"', 25),
        ("cloudflare_firewall", 'action=challenge ip=198.51.100.{oct} asn=AS64501 path=/customer/account/loginPost ua="Go-http-client/1.1"', 10),
        ("nginx_access", '203.0.113.{oct} "POST /customer/account/loginPost/ HTTP/1.1" 302 ua="python-requests/2.32"', 30),
        ("magento_system", "main.WARNING: Customer login failed: invalid credentials for email user{n}@example.com", 15),
    ],
    vendor_status={"cloudflare": "operational", "paypal": "operational", "aws": "operational"},
    truth=GroundTruth(
        root_cause="bot_attack",
        fixing_actions=frozenset({"cf_rate_limit_login", "cf_block_asn", "cf_managed_challenge", "cf_under_attack_mode"}),
        harmful_actions=frozenset({"scale_out_web", "raise_rate_limits"}),
        summary="Credential stuffing from two ASNs against /customer/account/loginPost.",
    ),
))

_register(Scenario(
    id="paypal_credential_expired",
    title="PayPal checkout failing: API credential expired",
    alert={"source": "cloudwatch", "name": "Checkout success rate below 40%",
           "severity": "critical", "service": "checkout"},
    metric_effects={"checkout_success": _x(0.12), "status_5xx": _x(3)},
    log_templates=[
        ("magento_exception", "Magento\\Paypal\\Model\\Api\\ProcessableException: PayPal NVP gateway errors: Security header is not valid (#10002: Security error)", 9),
        ("magento_system", "main.ERROR: PayPal Express SetExpressCheckout failed for quote {n}: Security header is not valid", 9),
        ("nginx_access", '192.0.2.{oct} "POST /paypal/express/start/ HTTP/1.1" 302', 10),
    ],
    events=[{"minute": 2, "type": "secrets_inventory",
             "detail": "PayPal API signature credential last rotated 365 days ago (policy: expires after 12 months)"}],
    vendor_status={"cloudflare": "operational", "paypal": "operational", "aws": "operational"},
    truth=GroundTruth(
        root_cause="paypal_credential_expired",
        fixing_actions=frozenset({"rotate_paypal_credentials"}),
        harmful_actions=frozenset({"disable_paypal"}),
        summary="PayPal API signature credential expired; every SetExpressCheckout returns 10002.",
    ),
))

_register(Scenario(
    id="paypal_outage",
    title="PayPal checkout failing: PayPal-side outage",
    alert={"source": "cloudwatch", "name": "Checkout success rate below 40%",
           "severity": "critical", "service": "checkout"},
    metric_effects={"checkout_success": _x(0.15), "p95_ms": _x(1.8), "status_5xx": _x(4)},
    log_templates=[
        ("magento_exception", "Magento\\Framework\\HTTP\\Adapter\\Curl: Operation timed out after 30001 milliseconds connecting to api-3t.paypal.com", 8),
        ("magento_system", "main.ERROR: PayPal Express SetExpressCheckout failed for quote {n}: HTTP 503 Service Unavailable", 8),
        ("nginx_access", '192.0.2.{oct} "POST /paypal/express/start/ HTTP/1.1" 504', 9),
    ],
    vendor_status={"cloudflare": "operational", "paypal": "major_outage", "aws": "operational"},
    truth=GroundTruth(
        root_cause="paypal_outage",
        fixing_actions=frozenset({"enable_backup_payment", "post_status_banner"}),
        harmful_actions=frozenset({"rotate_paypal_credentials", "restart_php_fpm"}),
        summary="PayPal API returning 503/timeouts; nothing wrong on our side.",
    ),
))

_register(Scenario(
    id="redis_session_failure",
    title="Customers cannot log in: Redis session store out of memory",
    alert={"source": "cloudwatch", "name": "Login success rate below 50% + 5xx on /customer",
           "severity": "high", "service": "accounts"},
    metric_effects={"login_success": _x(0.2), "status_5xx": _x(40), "redis_memory_pct": _set(100),
                    "checkout_success": _x(0.5), "p95_ms": _x(1.6)},
    log_templates=[
        ("magento_exception", "CredisException: OOM command not allowed when used memory > 'maxmemory' (redis-sessions:6379)", 12),
        ("magento_exception", "Cm\\RedisSession\\ConnectionFailedException: read error on connection to redis-sessions:6379", 6),
        ("nginx_access", '192.0.2.{oct} "POST /customer/account/loginPost/ HTTP/1.1" 503', 15),
    ],
    events=[{"minute": 5, "type": "cloudwatch_alarm", "detail": "ElastiCache sessions DatabaseMemoryUsagePercentage >= 99%"}],
    vendor_status={"cloudflare": "operational", "paypal": "operational", "aws": "operational"},
    truth=GroundTruth(
        root_cause="redis_session_failure",
        fixing_actions=frozenset({"redis_failover_resize", "flush_expired_sessions"}),
        harmful_actions=frozenset({"flush_all_redis"}),
        summary="Session Redis hit maxmemory (noeviction); new sessions cannot be written.",
    ),
    probes={"login_page": 503},
))

_register(Scenario(
    id="stale_static_content",
    title="Broken page layout after deploy: stale static content / CDN cache",
    alert={"source": "synthetic_check", "name": "Homepage visual check failed + 404 on /static",
           "severity": "medium", "service": "storefront"},
    metric_effects={"status_404": _x(60), "checkout_success": _x(0.55), "cache_hit_ratio": _set(0.93)},
    log_templates=[
        ("nginx_access", '192.0.2.{oct} "GET /static/version1761400000/frontend/Theme/default/en_US/css/styles-m.css HTTP/1.1" 404', 30),
        ("nginx_access", '192.0.2.{oct} "GET /static/version1761400000/frontend/Theme/default/en_US/requirejs-config.js HTTP/1.1" 404', 20),
        ("magento_system", "main.INFO: Static content version mismatch: deployed_version.txt=1761403600, cached HTML references 1761400000", 1),
    ],
    events=[{"minute": -3, "type": "deploy",
             "detail": "Release 2.4.8-p3 deployed: setup:upgrade ran, setup:static-content:deploy skipped (--skip-static)"}],
    vendor_status={"cloudflare": "operational", "paypal": "operational", "aws": "operational"},
    truth=GroundTruth(
        root_cause="stale_static_content",
        fixing_actions=frozenset({"static_content_deploy", "rollback_release"}),
        harmful_actions=frozenset({"rollback_database"}),
        summary="Deploy skipped static-content:deploy; CDN-cached HTML points at missing assets.",
    ),
    probes={"static_css": 404},
    state={"static_dir_present": False},
))

_register(Scenario(
    id="viral_promo_traffic",
    title="Traffic spike from viral Halloween promotion (legitimate customers)",
    alert={"source": "cloudflare", "name": "Traffic spike + elevated 429",
           "severity": "high", "service": "storefront"},
    metric_effects={
        "requests": _x(6.5), "unique_ips": _x(14), "status_429": _x(150), "p95_ms": _x(2.9),
        "origin_cpu_pct": _set(91), "login_attempts": _x(4), "login_success": _x(3.7),
        "checkout_attempts": _x(5), "checkout_success": _x(3.4), "cache_hit_ratio": _x(0.7),
    },
    log_templates=[
        ("nginx_access", '192.0.2.{oct} "GET /halloween-sale.html?utm_source=instagram HTTP/2" 200 ua="Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X)"', 30),
        ("cloudflare_firewall", 'action=block rule=rate_limit_global ip=198.51.100.{oct} asn=AS64510 path=/halloween-sale.html ua="Mozilla/5.0 (Linux; Android 15)"', 12),
        ("magento_system", "main.INFO: Order #{n} placed via checkout (promo HALLOWEEN40)", 6),
    ],
    events=[{"minute": -2, "type": "marketing_campaign",
             "detail": "Email + Instagram campaign 'Halloween 40% off' sent to 120,000 subscribers"}],
    vendor_status={"cloudflare": "operational", "paypal": "operational", "aws": "operational"},
    truth=GroundTruth(
        root_cause="viral_promo_traffic",
        fixing_actions=frozenset({"scale_out_web", "raise_rate_limits", "warm_full_page_cache"}),
        harmful_actions=frozenset({"cf_block_asn", "cf_rate_limit_login", "cf_managed_challenge", "cf_under_attack_mode"}),
        summary="Legitimate customers from a promotion; blocking them would lose revenue.",
    ),
))


def list_scenarios() -> list[dict]:
    return [{"id": s.id, "title": s.title, "service": s.alert["service"]} for s in SCENARIOS.values()]


def get_scenario(scenario_id: str) -> Scenario:
    try:
        return SCENARIOS[scenario_id]
    except KeyError as exc:
        raise KeyError(f"Unknown scenario '{scenario_id}'. Known: {sorted(SCENARIOS)}") from exc


# ---------------------------------------------------------------------------------------------------------
# Stack scenarios: one service of the reference stack fails. These mirror the fault drills that can be run
# on a real dev server (ops/drills.py in the capstone repo), so simulated and live runs are comparable.
_register(Scenario(
    id="valkey_down",
    title="Whole storefront failing: Valkey (cache + sessions) is down",
    alert={"source": "synthetic_check", "name": "Homepage check failed (HTTP 503)", "severity": "critical",
           "service": "storefront"},
    metric_effects={"status_5xx": _x(150), "p95_ms": _x(0.6), "checkout_success": _x(0.0), "login_success": _x(0.0),
                    "redis_memory_pct": _set(0)},
    log_templates=[
        ("magento_exception", "main.CRITICAL: CredisException: Connection to Redis 127.0.0.1:6379 failed after 2 failures."
                              " Last Error : (111) Connection refused", 15),
        ("journal:valkey-server", "Stopped valkey-server.service - Advanced key-value store.", 1),
        ("nginx_access", '192.0.2.{oct} "GET / HTTP/2.0" 503', 20),
    ],
    services={"valkey-server": "inactive"},
    probes={"home": 503, "login_page": 503, "search": 503, "backend_health": 200},
    state={"valkey_reachable": False},
    vendor_status={"cloudflare": "operational", "paypal": "operational", "aws": "operational"},
    truth=GroundTruth(
        root_cause="valkey_down",
        fixing_actions=frozenset({"start_valkey"}),
        harmful_actions=frozenset({"flush_all_redis", "restart_php_fpm"}),
        summary="Valkey stopped; Magento cache and sessions both live there, so every dynamic page fails.",
    ),
))

_register(Scenario(
    id="opensearch_down",
    title="Search and category pages failing: OpenSearch is down",
    alert={"source": "synthetic_check", "name": "Search page check failed (HTTP 500)", "severity": "high",
           "service": "catalog"},
    metric_effects={"status_5xx": _x(25), "checkout_success": _x(0.6)},
    log_templates=[
        ("magento_exception", "main.CRITICAL: Could not ping search engine: No alive nodes found in your cluster", 10),
        ("magento_exception", "OpenSearch\\Common\\Exceptions\\NoNodesAvailableException: No alive nodes found in your cluster", 5),
        ("nginx_access", '192.0.2.{oct} "GET /catalogsearch/result/?q=shirt HTTP/2.0" 500', 8),
    ],
    services={"opensearch": "failed"},
    probes={"search": 500},
    vendor_status={"cloudflare": "operational", "paypal": "operational", "aws": "operational"},
    truth=GroundTruth(
        root_cause="opensearch_down",
        fixing_actions=frozenset({"start_opensearch"}),
        harmful_actions=frozenset({"restart_php_fpm", "flush_all_redis"}),
        summary="OpenSearch stopped (e.g. JVM out of memory); search and layered navigation fail.",
    ),
))

_register(Scenario(
    id="php_fpm_down",
    title="Uncached pages return 502: PHP-FPM is down",
    alert={"source": "synthetic_check", "name": "Login page check failed (HTTP 502)", "severity": "critical",
           "service": "storefront"},
    metric_effects={"status_5xx": _x(120), "login_success": _x(0.0), "checkout_success": _x(0.0),
                    "cache_hit_ratio": _x(1.1)},
    log_templates=[
        ("nginx_backend_error", "connect() to unix:/run/php/php-magento.sock failed (111: Connection refused) while connecting to upstream", 15),
        ("journal:php8.5-fpm", "Stopped php8.5-fpm.service - The PHP 8.5 FastCGI Process Manager.", 1),
        ("nginx_access", '192.0.2.{oct} "GET /customer/account/login/ HTTP/2.0" 503', 15),
    ],
    services={"php8.5-fpm": "inactive"},
    probes={"login_page": 503, "search": 503, "backend_health": 502},
    vendor_status={"cloudflare": "operational", "paypal": "operational", "aws": "operational"},
    truth=GroundTruth(
        root_cause="php_fpm_down",
        fixing_actions=frozenset({"start_php_fpm", "restart_php_fpm"}),
        harmful_actions=frozenset({"flush_all_redis"}),
        summary="PHP-FPM stopped; Varnish still serves cached pages, everything uncached fails with 502/503.",
    ),
))

_register(Scenario(
    id="cron_stopped",
    title="Order e-mails and indexers stalled: cron is not running",
    alert={"source": "cloudwatch", "name": "No Magento cron run in 5 minutes", "severity": "medium",
           "service": "backoffice"},
    metric_effects={},
    log_templates=[
        ("magento_system", "main.WARNING: Indexer catalogsearch_fulltext is invalid (backlog 1240 changes)", 2),
    ],
    services={"cron": "inactive"},
    state={"magento_cron_runs_5min": 0},
    vendor_status={"cloudflare": "operational", "paypal": "operational", "aws": "operational"},
    truth=GroundTruth(
        root_cause="cron_stopped",
        fixing_actions=frozenset({"start_cron"}),
        harmful_actions=frozenset({"rollback_release"}),
        summary="The cron service is stopped; Magento's queue consumers, e-mails and indexers stall silently.",
    ),
))

_register(Scenario(
    id="nginx_config_not_applied",
    title="nginx configuration changed but the running nginx still uses the old one",
    alert={"source": "drift_check", "name": "nginx config newer than running master process", "severity": "medium",
           "service": "edge"},
    metric_effects={},
    log_templates=[
        ("nginx_error", 'nginx: [emerg] limit_req_zone "general" uses the "$webinusa_limit_key" key while previously it '
                        'used the "$binary_remote_addr" key', 1),
    ],
    events=[{"minute": -1, "type": "config_change",
             "detail": "nginx configuration changed after the running master process started"}],
    state={"nginx_config_newer_than_master": True},
    vendor_status={"cloudflare": "operational", "paypal": "operational", "aws": "operational"},
    truth=GroundTruth(
        root_cause="nginx_config_not_applied",
        fixing_actions=frozenset({"nginx_test_and_restart"}),
        harmful_actions=frozenset({"rollback_release"}),
        summary="A reload was refused silently (changed limit zone key); only a restart applies the new config.",
    ),
))
