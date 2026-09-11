"""
tests/test_data_lineage_audit.py

PHASE 5 — REAL-DATA AUDIT & LIVE DATA ENFORCEMENT TEST SUITE

Validates:
1. Investigation Isolation: Investigation A assets/clusters CANNOT leak into Investigation B.
2. Provenance Metadata: RDAP and DNS intelligence include explicit source provenance.
3. Feed Failure Contract: Unreachable/disabled feeds return status UNAVAILABLE (not fake match=false).
4. Sender Baseline Disclosures: Sender telemetry reports source_classification SIMULATED_ORGANISATIONAL_BASELINE.
"""

import pytest
import sqlite3
from database import init_db, insert_scanned_asset, fetch_all_assets, get_db_connection
from services.rdap_service import fetch_rdap_data
from services.dns_intelligence_service import resolve_dns_records
from services.infrastructure_service import get_offender_clusters, find_linked_infrastructure
from services.sender_behavior import evaluate_sender_behavior
from services.threat_intelligence.phishtank_adapter import get_phishtank_health


@pytest.fixture(autouse=True)
def clean_db():
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM assets WHERE investigation_id LIKE 'test_inv_%'")
    conn.commit()
    conn.close()
    yield


def test_investigation_isolation_prevents_cross_leakage():
    """
    Proves Investigation A (Amazon) assets cannot leak into Investigation B (Microsoft).
    """
    # Insert Investigation A asset (Amazon)
    insert_scanned_asset(
        asset_type="domain",
        asset_id="amaz0n-security-login.xyz",
        ip_address="192.0.2.100",
        target_brand="Amazon",
        investigation_id="test_inv_amazon_01"
    )

    # Insert Investigation B asset (Microsoft)
    insert_scanned_asset(
        asset_type="domain",
        asset_id="microsoft-update-portal.online",
        ip_address="192.0.2.100",
        target_brand="Microsoft",
        investigation_id="test_inv_microsoft_02"
    )

    # Query assets strictly for Investigation B
    assets_b = fetch_all_assets(investigation_id="test_inv_microsoft_02")
    asset_ids_b = [a["asset_id"] for a in assets_b]

    assert "microsoft-update-portal.online" in asset_ids_b
    assert "amaz0n-security-login.xyz" not in asset_ids_b

    # Query offender clusters strictly for Investigation B
    clusters_b = get_offender_clusters(investigation_id="test_inv_microsoft_02")
    clustered_assets = []
    for c in clusters_b.get("clusters", []):
        clustered_assets.extend([a["asset_id"] for a in c.get("assets", [])])

    assert "amaz0n-security-login.xyz" not in clustered_assets


def test_rdap_provenance_metadata():
    """
    Verifies RDAP data returns explicit provenance metadata with live/retrieved_at status.
    """
    res = fetch_rdap_data("amazon.com", use_cache=True)
    assert "provenance" in res
    prov = res["provenance"]
    assert prov["source"] == "rdap"
    assert "live" in prov
    assert "retrieved_at" in prov
    assert prov["status"] in ["RDAP_SUCCESS", "RDAP_NOT_FOUND", "RDAP_UNAVAILABLE"]


def test_dns_provenance_metadata():
    """
    Verifies DNS resolution returns explicit provenance metadata.
    """
    res = resolve_dns_records("google.com", use_cache=True)
    assert "provenance" in res
    prov = res["provenance"]
    assert prov["source"] == "dns"
    assert "live" in prov
    assert "retrieved_at" in prov
    assert prov["status"] in ["DNS_SUCCESS", "DNS_NXDOMAIN", "DNS_ERROR"]


def test_sender_behavior_telemetry_disclosure():
    """
    Verifies sender behavior telemetry explicitly discloses SIMULATED_ORGANISATIONAL_BASELINE.
    """
    res = evaluate_sender_behavior(
        sender="finance@acme.example",
        subject="URGENT: Login",
        org_id="org_acme_01"
    )
    assert res.get("source_classification") == "SIMULATED_ORGANISATIONAL_BASELINE"
    assert res.get("profile_available") is True


def test_feed_health_reporting():
    """
    Verifies threat intelligence feed health returns structured status.
    """
    health = get_phishtank_health()
    assert health.source_name == "phishtank"
    assert health.status in ["AVAILABLE", "UNAVAILABLE", "DEGRADED"]
