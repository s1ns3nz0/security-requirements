"""Regression tests for the deterministic half of the pipeline.

Everything covered here is a lookup or an arithmetic step. The model-dependent
half -- threat modeling and requirement authoring -- is scored separately by
scripts/eval_golden.py, because there is no fixed answer to assert against.

Several tests exist because the week-1 tracer bullet found the bug they now
guard. Those are marked.
"""

from __future__ import annotations

import copy
import re
import json
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import classify_resp  # noqa: E402
import lint as lint_mod  # noqa: E402
import merge  # noqa: E402
import profile_schema  # noqa: E402
import select_baseline as sb  # noqa: E402

GOLDEN = REPO_ROOT / "golden" / "b2b-saas-aws"
GOLDEN_ROOT = REPO_ROOT / "golden"

# The four golden cases exist to keep the whole range of the scale reachable.
# If every profile lands on Moderate, the derivation is not discriminating and
# the tailoring is decorative.
EXPECTED_IMPACT = {
    "internal-admin": "low",
    "b2b-saas-aws": "moderate",
    "mobile-backend": "moderate",
    "commerce-payments": "high",
}


def load_golden(name: str) -> dict:
    return yaml.safe_load((GOLDEN_ROOT / name / "profile.yaml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def profile():
    return yaml.safe_load((GOLDEN / "profile.yaml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def derived(profile):
    return sb.run(profile)


@pytest.fixture(scope="module")
def threats():
    return yaml.safe_load((GOLDEN / "threats.yaml").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# catalog integrity
# ---------------------------------------------------------------------------

def test_catalog_is_built():
    assert (REPO_ROOT / "catalogs" / "nist-800-53r5" / "baselines.json").exists(), \
        "run scripts/rebuild_catalogs.py first"


def test_baseline_sizes_match_publication():
    path = REPO_ROOT / "catalogs" / "nist-800-53r5" / "baselines.json"
    baselines = json.loads(path.read_text(encoding="utf-8"))
    # SP 800-53B. A change here means the upstream release moved and the
    # curation needs revisiting, not that the test is wrong.
    assert len(baselines["low"]) == 149
    assert len(baselines["moderate"]) == 287
    assert len(baselines["high"]) == 370


def test_all_twenty_families_are_bundled():
    meta = json.loads((REPO_ROOT / "catalogs" / "nist-800-53r5" / "meta.json").read_text(encoding="utf-8"))
    assert len(meta["families_extracted"]) == 20
    assert meta["partial"] is False


def test_csf_matches_published_structure():
    """Regression: the OSCAL release carries CSF 1.1 alongside 2.0.

    Taken whole it yields 185 subcategories across 34 categories. Filtering the
    entries marked withdrawn, and the categories outside the published CSF 2.0
    set, must land on exactly the 106 and 22 that NIST publishes. Anything else
    means the filter drifted and the bundled structure is wrong.
    """
    meta = json.loads((REPO_ROOT / "catalogs" / "csf-2.0" / "meta.json").read_text(encoding="utf-8"))
    assert meta["subcategory_count"] == 106
    assert meta["category_count"] == 22


def test_asvs_is_bundled_with_its_licence():
    asvs = REPO_ROOT / "catalogs" / "asvs-5"
    meta = json.loads((asvs / "meta.json").read_text(encoding="utf-8"))
    assert meta["requirement_count"] > 300
    assert meta["license"] == "CC BY-SA 4.0"
    # The share-alike condition is confined by keeping the adapted material in
    # its own directory with its own licence and a statement of changes.
    assert (asvs / "LICENSE").exists()
    assert (asvs / "NOTICE").exists()
    assert "CC BY-SA 4.0" in (asvs / "LICENSE").read_text(encoding="utf-8")


def test_no_unresolved_parameter_placeholders():
    """Regression: select choices nest parameter references two levels deep.

    AC-7's lockout options embed further placeholders, and sibling enhancements
    reference each other's parameters (SC-42(2) uses one declared on SC-42(1)).
    Both leaked raw internal ids such as `ac-07_odp.04` into control statements.
    """
    for path in (REPO_ROOT / "catalogs" / "nist-800-53r5").glob("*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            assert "_odp" not in record["statement"], record["id"]
            assert "_prm_" not in record["statement"], record["id"]


def test_enhancement_identifiers_use_audit_notation():
    ids = lint_mod.load_catalog_ids()
    assert "SC-28(1)" in ids
    assert "sc-28.1" not in ids


# ---------------------------------------------------------------------------
# impact derivation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,expected", sorted(EXPECTED_IMPACT.items()))
def test_golden_cases_span_the_scale(name, expected):
    """Every level must be reachable.

    Two regressions live here. Credentials were categorised as business
    information, which put every consumer application on the High baseline.
    Audit log integrity was a fixed Moderate, which put every system that keeps
    audit logs -- that is, every system -- at Moderate or above and made Low
    unreachable. Both produced documents nobody would act on.
    """
    result = sb.run(load_golden(name))
    assert result["impact"]["system"] == expected


def test_no_undetermined_responsibility_for_any_golden_case():
    for name in EXPECTED_IMPACT:
        profile = load_golden(name)
        derived = sb.run(profile)
        result = classify_resp.classify(profile, derived["controls"])
        assert result["counts"]["undetermined"] == 0, f"{name} has unmapped controls"


def test_ordinary_b2b_saas_lands_on_moderate(derived):
    """Regression: a commercial SaaS was landing on the High baseline.

    FIPS 199 reserves High for severe or catastrophic effect. Tampered
    settlement records are serious and recoverable. Inflating any single axis
    drags the whole system to High through the high water mark and produces a
    370-control document the team discards.
    """
    assert derived["impact"]["system"] == "moderate"
    assert derived["baseline"] == "nist-800-53b-moderate"


def test_rpo_zero_does_not_imply_high_availability(profile):
    """Regression: RPO and RTO answer different questions.

    Zero tolerable data loss is a durability property. A service may accept
    hours of downtime and no data loss at the same time.
    """
    result = sb.run(profile)
    assert result["impact"]["availability"]["level"] == "moderate"


def test_tokenisation_reduces_confidentiality(profile):
    without = copy.deepcopy(profile)
    for entry in without["declared"]["data_types"]:
        if entry.get("id") == "payment_token":
            entry.pop("modifiers", None)
    reasons = sb.run(without)["impact"]["confidentiality"]["because"]
    assert any("PSP tokens" in r and r.endswith("moderate") for r in reasons)

    reasons = sb.run(profile)["impact"]["confidentiality"]["because"]
    assert any("PSP tokens" in r and r.endswith("low") for r in reasons)


def test_encryption_is_not_an_accepted_modifier(profile):
    """Encryption is the outcome of a requirement, not a property of the data.

    Accepting it as grounds for reduction lets a requirement delete itself.
    """
    table = yaml.safe_load(
        (REPO_ROOT / "catalogs" / "data-types" / "classification.yaml").read_text(encoding="utf-8")
    )
    rejected = {m["id"] for m in table["rejected_modifiers"]}
    assert "encrypted_at_rest" in rejected
    assert "encrypted_at_rest" not in table["modifiers"]

    broken = copy.deepcopy(profile)
    broken["declared"]["data_types"][0] = {"id": "basic_contact", "modifiers": ["encrypted_at_rest"]}
    with pytest.raises(sb.ProfileError):
        sb.run(broken)


def test_backups_inherit_the_highest_level(profile):
    reasons = sb.run(profile)["impact"]["confidentiality"]["because"]
    assert any("backups" in r.lower() and "inherits" in r for r in reasons)


def test_credentials_are_excluded_from_the_water_mark(profile):
    """Regression: adding credentials to a Moderate profile forced it to High.

    FIPS 199 categorises a system by the business information it holds.
    Credentials are system information and are present in nearly every service.
    """
    with_creds = copy.deepcopy(profile)
    with_creds["declared"]["data_types"].append({"id": "account_credentials"})
    result = sb.run(with_creds)
    assert result["impact"]["system"] == "moderate"
    assert any("system information" in r for r in result["impact"]["confidentiality"]["because"])


def test_audit_logs_do_not_raise_a_low_system(profile):
    """Regression: a fixed Moderate on audit log integrity made Low unreachable."""
    low = copy.deepcopy(profile)
    low["declared"]["data_types"] = [{"id": "internal_ops"}, {"id": "audit_logs"}, {"id": "app_logs"}]
    low["declared"]["availability"] = {
        "rto": "rto_day_plus", "rpo": "rpo_hours_plus", "amplifiers": ["internal_tool_only"],
    }
    assert sb.run(low)["impact"]["system"] == "low"


def test_safety_critical_forces_high_availability(profile):
    critical = copy.deepcopy(profile)
    critical["declared"]["availability"]["amplifiers"] = ["safety_critical"]
    assert sb.run(critical)["impact"]["availability"]["level"] == "high"


def test_single_axis_driver_is_surfaced():
    """Found by running against a real repository.

    A document store whose data was Low on both confidentiality and integrity
    still landed on Moderate, because it should recover within the business
    day. The high water mark is the rule, but it hides which answer did the
    work -- and that one interview answer is the difference between 149
    controls and 287. Without naming it, the only reviewable thing about the
    categorisation is its conclusion.
    """
    single = {
        "declared": {
            "data_types": [{"id": "internal_ops"}, {"id": "app_logs"}],
            "availability": {"rto": "rto_hours", "rpo": "rpo_hours_plus", "amplifiers": []},
            "user_regions": ["KR"],
        }
    }
    driver = sb.run(single)["impact"]["driver"]
    assert driver is not None
    assert driver["axis"] == "availability"
    assert driver["level_without"] == "low"
    assert driver["control_count_without"] < driver["control_count"]


@pytest.mark.parametrize("name", sorted(EXPECTED_IMPACT))
def test_no_spurious_single_axis_claim(name):
    """Silent when two or more axes sit at the system level -- otherwise the
    warning appears everywhere and stops being read."""
    result = sb.run(load_golden(name))
    impact = result["impact"]
    axes = [impact[a]["level"] for a in ("confidentiality", "integrity", "availability")]
    if axes.count(impact["system"]) > 1:
        assert impact["driver"] is None


def test_user_override_is_recorded(profile):
    overridden = copy.deepcopy(profile)
    overridden["derived"] = {"impact": {"override": {"system": "low", "reason": "pilot only"}}}
    result = sb.run(overridden)
    assert result["impact"]["system"] == "low"
    assert result["impact"]["overridden_by_user"] is True
    assert result["impact"]["override_reason"] == "pilot only"


# ---------------------------------------------------------------------------
# jurisdiction
# ---------------------------------------------------------------------------

def test_gdpr_does_not_fire_for_korean_and_japanese_users(derived):
    """Regression: GDPR fired on data type alone, ignoring jurisdiction.

    A false trigger costs the reader's trust in every other finding.
    """
    uncovered = {item["id"] for item in derived["uncovered_regulations"]}
    triggered = uncovered | {t["id"] for item in derived["overlay_triggers"] for t in item["triggers"]}
    assert "gdpr_personal_data" not in triggered
    # PIPA now routes to its overlay rather than being declared uncovered, but
    # the trigger must still fire.
    assert "pipa_general" in triggered


def test_gdpr_fires_for_eu_users(profile):
    """GDPR now routes to its overlay rather than being declared uncovered, but
    the trigger must still fire."""
    eu = copy.deepcopy(profile)
    eu["declared"]["user_regions"] = ["DE"]
    result = sb.run(eu)
    triggered = ({t["id"] for t in result["uncovered_regulations"]}
                 | {x["id"] for t in result["overlay_triggers"] for x in t["triggers"]})
    assert "gdpr_personal_data" in triggered
    assert "gdpr" in result["applicable_overlays"]


def test_pci_always_fires_regardless_of_region(profile):
    """Card scheme rules are contractual, not territorial. PCI now routes to its
    overlay rather than being declared uncovered, but the trigger must fire
    wherever the users are."""
    card = copy.deepcopy(profile)
    card["declared"]["data_types"].append({"id": "payment_card_raw"})
    card["declared"]["user_regions"] = ["BR"]
    result = sb.run(card)
    triggered = ({t["id"] for t in result["uncovered_regulations"]}
                 | {x["id"] for t in result["overlay_triggers"] for x in t["triggers"]})
    assert "pci_dss" in triggered
    assert "pci-dss" in result["applicable_overlays"]


def test_cross_border_transfer_detected(derived):
    cb = derived["cross_border"]
    assert cb is not None
    assert cb["storage_country"] == "KR"
    assert "JP" in cb["offshore_for"]


def test_unknown_region_is_undetermined_not_guessed(profile):
    unknown = copy.deepcopy(profile)
    unknown["inferred"]["region_storage"] = "moon-central-1"
    assert sb.run(unknown)["cross_border"]["undetermined"] is True


# ---------------------------------------------------------------------------
# responsibility
# ---------------------------------------------------------------------------

def test_uncurated_services_are_reported(profile, derived):
    """A service with no curated file must be named, not silently absorbed.

    The alternative is a matrix that looks equally confident everywhere, and a
    reader with no way to tell which parts were actually reviewed.
    """
    with_unknown = copy.deepcopy(profile)
    with_unknown["inferred"]["managed_services"].append(
        {"id": "aws-bedrock", "evidence": "src/llm/client.ts:8"}
    )
    result = classify_resp.classify(with_unknown, derived["controls"])
    assert "aws-bedrock" in result["services_uncurated"]
    assert "aws-s3" in result["services_curated"]


def test_curated_services_cover_the_common_aws_surface(profile, derived):
    result = classify_resp.classify(profile, derived["controls"])
    assert result["services_uncurated"] == []


def test_service_curation_overrides_the_layer(profile, derived):
    result = classify_resp.classify(profile, derived["controls"])
    entry = next(e for e in result["controls"] if e["control"] == "AC-3")
    assert entry["source"].startswith("services/")
    assert entry["responsibility"] == "team"


def test_shared_entries_state_both_halves(profile, derived):
    """Collapsing shared into provider-claimed is how gaps go unowned."""
    result = classify_resp.classify(profile, derived["controls"])
    entry = next(e for e in result["controls"] if e["control"] == "SC-28")
    service = next(s for s in entry["services"] if s["service"] == "aws-s3")
    assert service["responsibility"] == "shared"
    assert service["csp_part"] and service["team_part"]
    assert service["evidence"]


def test_the_split_actually_filters(profile, derived):
    result = classify_resp.classify(profile, derived["controls"])
    reaching_team = result["counts"]["team"] + result["counts"]["shared"]
    assert reaching_team < len(derived["controls"])
    assert result["counts"]["org"] > 0


def test_deployment_model_override_applies(profile, derived):
    serverless = classify_resp.classify(profile, ["SC-39"])
    assert serverless["controls"][0]["responsibility"] == "csp_claimed"

    onprem = copy.deepcopy(profile)
    onprem["inferred"]["deployment_model"] = "onprem"
    onprem["inferred"]["managed_services"] = []
    assert classify_resp.classify(onprem, ["SC-39"])["controls"][0]["responsibility"] == "team"


def test_patching_moves_with_the_deployment_model(profile):
    """SI-2 is the clearest case: on serverless the provider patches the
    runtime, on self-managed instances the team does. Getting this backwards
    either hands the team work that is not theirs or drops work that is."""
    serverless = classify_resp.classify(profile, ["SI-2"])["controls"][0]
    assert serverless["responsibility"] == "shared"

    iaas = copy.deepcopy(profile)
    iaas["inferred"]["deployment_model"] = "iaas"
    iaas["inferred"]["managed_services"] = []
    assert classify_resp.classify(iaas, ["SI-2"])["controls"][0]["responsibility"] == "team"


def test_service_entry_can_be_conditional_on_deployment_model(profile):
    """Found by running against a real repository.

    aws-ecs.yaml claimed SC-39 as provider-isolated unconditionally, with the
    EC2 caveat written only as a prose note. Against an EC2 launch type service
    the classifier therefore asserted an isolation boundary that does not exist
    -- the exact failure this tool is built to prevent, committed by its own
    curation. An entry that does not apply must fall through to the layer.
    """
    on_ecs = copy.deepcopy(profile)
    on_ecs["inferred"]["managed_services"] = [{"id": "aws-ecs"}]

    fargate = classify_resp.classify(on_ecs, ["SC-39"])["controls"][0]
    assert fargate["responsibility"] == "csp_claimed"
    assert fargate["source"] == "services/aws-ecs.yaml"

    on_ecs["inferred"]["deployment_model"] = "iaas"
    ec2 = classify_resp.classify(on_ecs, ["SC-39"])["controls"][0]
    assert ec2["responsibility"] == "team"
    assert ec2["source"] == "layers.yaml:iaas"


# ---------------------------------------------------------------------------
# profile normalisation
#
# Every rule downstream compares a user-authored string against a fixed set, and
# each comparison was written as an exact match. Probing the value space found
# five failures at once, three of them silent and in the direction that
# suppresses findings. These tests hold the whole class shut rather than the
# five instances.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("written,expected", [
    ("serverless", "serverless"), ("Serverless", "serverless"),
    ("SERVERLESS", "serverless"), ("  iaas  ", "iaas"), ("IaaS", "iaas"),
    ("k8s", "kubernetes"), ("K8s", "kubernetes"), ("eks", "kubernetes"),
    ("on-prem", "onprem"), ("On-Premises", "onprem"), ("iot", "embedded"),
])
def test_deployment_model_spelling_is_normalised(profile, written, expected):
    p = copy.deepcopy(profile)
    p["inferred"]["deployment_model"] = written
    result = classify_resp.classify(p, ["SC-39"])
    assert result["deployment_model"] == expected
    assert result["deployment_model_recognised"] is True


def test_a_scalar_where_a_list_belongs_is_coerced_and_reported(profile):
    """`entrypoints: "http: api"` iterated as characters, so the shape detector
    read an HTTP API as not-a-service and suppressed the ASVS level."""
    p = copy.deepcopy(profile)
    p["inferred"]["entrypoints"] = "http: api"
    result = sb.run(p)
    assert result["shape"]["shape"] == "service"
    assert result["asvs_level"] is not None
    assert any("entrypoints" in w for w in result["schema_warnings"])


def test_scalar_user_regions_do_not_suppress_triggers(profile):
    """`user_regions: "KR"` became {"K", "R"}, matched no jurisdiction, and
    silenced every regulatory trigger -- a failure in the direction that hides
    findings."""
    p = copy.deepcopy(profile)
    p["declared"]["user_regions"] = "KR"
    result = sb.run(p)
    triggered = ({t["id"] for t in result["uncovered_regulations"]}
                 | {x["id"] for t in result["overlay_triggers"] for x in t["triggers"]})
    assert "pipa_general" in triggered


@pytest.mark.parametrize("written", ["ap-northeast-2", "AP-NORTHEAST-2", " ap-northeast-2 "])
def test_region_spelling_does_not_lose_cross_border(profile, written):
    p = copy.deepcopy(profile)
    p["inferred"]["region_storage"] = written
    assert sb.run(p)["cross_border"]["storage_country"] == "KR"


@pytest.mark.parametrize("written", [["sso"], ["SSO"], "sso", [" SSO "]])
def test_org_control_spelling_keeps_its_annotations(profile, written):
    """IA-2 rather than AC-2. AC-2 carried this until the coverage table was cut
    back: company-wide SSO performs identification and authentication, and does
    not discharge account lifecycle management for the application."""
    p = copy.deepcopy(profile)
    p["declared"]["existing_org_controls"] = written
    result = classify_resp.classify(p, ["IA-2", "AU-6"])
    assert any(e.get("org_control_declared") for e in result["controls"])


@pytest.mark.parametrize("value,field", [
    ([123], "data_types"),
    ([None, "KR"], "user_regions"),
])
def test_unrescuable_values_raise_rather_than_drop(profile, value, field):
    """Dropping a malformed data type silently changes the derivation, and the
    reader would never learn that it had."""
    p = copy.deepcopy(profile)
    p["declared"][field] = value
    with pytest.raises(profile_schema.SchemaError):
        sb.run(p)


def test_forced_requirements_are_produced(profile):
    """Found by sweeping an Azure SOC platform.

    `forces_requirements` was declared on four data types and documented in
    requirement-style.md and the build command, and no script read it. The tool
    documented a behaviour it did not have -- the implied-coverage failure it
    exists to prevent. It also meant system-information types produced nothing
    at all: excluded from the water mark, and with their forced requirements
    dropped, a service full of secrets got no secret-handling requirement.
    """
    with_secrets = copy.deepcopy(profile)
    with_secrets["declared"]["data_types"] = [
        {"id": "internal_ops"}, {"id": "config_secrets"}, {"id": "app_logs"},
    ]
    forced = sb.run(with_secrets)["forced_requirements"]
    ids = {f["id"] for f in forced}
    assert "secret_management" in ids
    assert "log_sanitization" in ids
    assert all(f["sources"] and f["label"] for f in forced)
    assert all(src["data_type"] and src["label"] for f in forced for src in f["sources"])


def test_forced_requirements_reach_the_work_list(profile):
    """They must survive the crossing, or the derivation drops them again one
    step later."""
    with_secrets = copy.deepcopy(profile)
    with_secrets["declared"]["data_types"] = [{"id": "internal_ops"}, {"id": "config_secrets"}]
    derived = sb.run(with_secrets)
    resp = classify_resp.classify(with_secrets, derived["controls"])
    crossed = merge.cross(derived, resp, {"threats": []})
    assert crossed["counts"].get("forced_by_data_type", 0) >= 1


def test_data_held_for_a_customer_forces_processor_obligations(profile):
    """Found by sweeping a scanner that ingests customers' Terraform plans.

    Every data type is written from the holder's point of view -- source code is
    "loss of competitive position" -- so a service holding someone else's data
    derived as though the harm and the duties were its own. Nothing produced a
    processing agreement, a deletion-on-instruction, or a notify-the-owner
    requirement, because no control is keyed on whose data it is.
    """
    processor = copy.deepcopy(profile)
    processor["declared"]["data_types"] = [
        {"id": "source_code_ip", "modifiers": ["customer_owned"]},
        {"id": "app_logs"},
    ]
    result = sb.run(processor)
    assert "data_processor_obligations" in {f["id"] for f in result["forced_requirements"]}
    assert "processor_role" in result["threat_flags"]

    # Holding data for someone else does not make that data more sensitive.
    own = copy.deepcopy(processor)
    own["declared"]["data_types"][0].pop("modifiers")
    assert sb.run(own)["impact"]["confidentiality"]["level"] == \
        result["impact"]["confidentiality"]["level"]


def test_availability_hint_is_gone(profile):
    """config_secrets once carried availability_hint: high. Nothing read it, and
    wiring it would have driven availability to High for every service that
    holds secrets -- which is every service."""
    table = yaml.safe_load(
        (REPO_ROOT / "catalogs" / "data-types" / "classification.yaml").read_text(encoding="utf-8")
    )
    assert not any("availability_hint" in t for t in table["types"])


def test_no_provider_means_no_provider_claims(profile):
    """Found by sweeping an on-premise profile with csp: none.

    Fifteen PE/MP/CP controls were assigned csp_claimed -- a claim against a
    provider that does not exist -- because the onprem override list enumerated
    some controls and missed the rest. The rule is structural: with no cloud
    provider in the profile, csp_claimed is not a legal outcome.
    """
    onprem = copy.deepcopy(profile)
    onprem["inferred"]["csp"] = "none"
    onprem["inferred"]["deployment_model"] = "onprem"
    onprem["inferred"]["managed_services"] = []
    result = classify_resp.classify(onprem, ["PE-4", "PE-8", "MP-3", "CP-8(1)", "SI-8(2)"])
    assert all(e["responsibility"] != "csp_claimed" for e in result["controls"])
    assert any(e["source"].endswith("+no-csp") for e in result["controls"])


def test_asvs_not_issued_without_an_app_surface(profile):
    """Found by sweeping a pure-IaC repository and a pip library: both were
    issued an ASVS level. ASVS is an application standard; asserting it for a
    Terraform repo claims an applicable standard that is not."""
    iac_only = copy.deepcopy(profile)
    iac_only["inferred"]["entrypoints"] = []
    result = sb.run(iac_only)
    assert result["asvs_level"] is None
    assert result["shape"]["shape"] == "no_entrypoints"

    library = copy.deepcopy(profile)
    library["inferred"]["entrypoints"] = ["library import", "cli"]
    result = sb.run(library)
    assert result["asvs_level"] is None
    assert result["shape"]["shape"] == "non_service"

    assert sb.run(profile)["asvs_level"] is not None  # real service keeps its level


def test_unknown_deployment_model_is_flagged(profile):
    """Found by sweeping a profile that said "kubernetes". An unrecognised
    model silently disabled every model override and applies_when condition --
    a typo would degrade the whole layer with no visible symptom.

    Kubernetes was subsequently added as a model, so the check uses a value that
    is genuinely unknown.
    """
    typo = copy.deepcopy(profile)
    typo["inferred"]["deployment_model"] = "serverles"
    assert classify_resp.classify(typo, ["SC-39"])["deployment_model_recognised"] is False

    assert classify_resp.classify(profile, ["SC-39"])["deployment_model_recognised"] is True

    k8s = copy.deepcopy(profile)
    k8s["inferred"]["deployment_model"] = "kubernetes"
    k8s["inferred"]["managed_services"] = []   # test the layer, not a service override
    result = classify_resp.classify(k8s, ["SC-7"])
    assert result["deployment_model_recognised"] is True
    # Without a NetworkPolicy every pod reaches every other pod, so the boundary
    # is the team's to draw rather than the provider's to supply.
    assert result["controls"][0]["responsibility"] == "team"
    assert result["controls"][0]["source"] == "layers.yaml:kubernetes"


def test_physical_controls_are_the_team_s_on_an_embedded_system(profile):
    """Found by sweeping a UAV assessment repository.

    All forty-seven PE, MA, and MP controls landed in the organisational bucket
    because `onprem` was the closest available model. That is right for a
    datacenter and wrong for an airframe: tamper resistance, debug port
    lockdown, and firmware media handling are engineering work.
    """
    device = copy.deepcopy(profile)
    device["inferred"]["csp"] = "none"
    device["inferred"]["deployment_model"] = "embedded"
    device["inferred"]["managed_services"] = []
    physical = ["PE-3", "PE-4", "MA-3", "MP-6", "SR-11"]
    result = classify_resp.classify(device, physical)
    assert all(e["responsibility"] == "team" for e in result["controls"])

    facility = copy.deepcopy(device)
    facility["inferred"]["deployment_model"] = "onprem"
    result = classify_resp.classify(facility, ["PE-3", "MA-3"])
    assert all(e["responsibility"] == "org" for e in result["controls"])


@pytest.mark.parametrize("value", [
    "none", "None", "NONE", None, "", "n/a", "-", "self-hosted", "on-prem", "  none  ",
])
def test_every_spelling_of_no_provider_blocks_claims(profile, value):
    """Found by probing the rule added one round earlier.

    It matched the literal string "none" and nothing else, so `None`, `n/a`,
    `-`, `self-hosted`, and `on-prem` all restored inheritance claims against a
    provider that does not exist -- reintroducing, through ordinary spellings,
    exactly the bug the rule had just been written to fix.
    """
    p = copy.deepcopy(profile)
    p["inferred"]["csp"] = value
    p["inferred"]["deployment_model"] = "onprem"
    p["inferred"]["managed_services"] = []
    result = classify_resp.classify(p, ["PE-4", "PE-8", "MP-3", "CP-8(1)", "SI-8(2)"])
    assert all(e["responsibility"] != "csp_claimed" for e in result["controls"])
    assert result["csp_status"] == "none"


def test_unrecognised_provider_claims_nothing(profile):
    """A claim needs a claimant. If the provider cannot be identified, no
    evidence can be named for it, so no inheritance may be asserted."""
    p = copy.deepcopy(profile)
    p["inferred"]["csp"] = "weirdcloud"       # not a provider this repository knows
    p["inferred"]["deployment_model"] = "iaas"
    p["inferred"]["managed_services"] = []
    result = classify_resp.classify(p, ["PE-4", "MP-3"])
    assert result["csp_status"] == "unrecognised"
    assert all(e["responsibility"] != "csp_claimed" for e in result["controls"])


def test_multiple_providers_are_flagged(profile):
    """Shared responsibility differs per provider, so one split cannot cover
    two. Found on a Terraform repository with interchangeable S3 and GCS
    adapters, where a list-valued csp passed silently."""
    p = copy.deepcopy(profile)
    p["inferred"]["csp"] = ["aws", "gcp"]
    result = classify_resp.classify(p, ["SC-7"])
    assert result["csp_status"] == "multiple"
    assert result["csp_declared"] == ["aws", "gcp"]


def test_provider_model_without_a_provider_is_flagged(profile):
    """Found on a static site profile declaring saas with csp: none. The
    combination is incoherent and resolved silently, because the no-provider
    rule then turned every inherited control organisational without comment."""
    contradictory = copy.deepcopy(profile)
    contradictory["inferred"]["csp"] = "none"
    contradictory["inferred"]["deployment_model"] = "saas"
    assert classify_resp.classify(contradictory, ["SC-7"])["csp_model_inconsistent"] is True

    coherent = copy.deepcopy(profile)
    coherent["inferred"]["csp"] = "none"
    coherent["inferred"]["deployment_model"] = "embedded"
    assert classify_resp.classify(coherent, ["SC-7"])["csp_model_inconsistent"] is False
    assert classify_resp.classify(profile, ["SC-7"])["csp_model_inconsistent"] is False


def test_family_default_covers_unlisted_controls(profile):
    """A control with no rule of its own must resolve, not fall to UNDETERMINED.

    PS-9 has no override anywhere; it should follow the PS family default.
    """
    entry = classify_resp.classify(profile, ["PS-9"])["controls"][0]
    assert entry["responsibility"] == "org"
    assert entry["source"] == "layers.yaml:family"


def test_enhancement_follows_its_base_control(profile):
    """CP-6(1) has no rule of its own and must follow CP-6 rather than the CP
    family default, which is org."""
    entry = classify_resp.classify(profile, ["CP-6(1)"])["controls"][0]
    assert entry["responsibility"] == "shared"


def test_physical_controls_never_reach_a_cloud_team(profile, derived):
    result = classify_resp.classify(profile, derived["controls"])
    physical = [e for e in result["controls"] if e["control"].startswith("PE-") and e["control"] != "PE-1"]
    assert physical
    assert all(e["responsibility"] in ("csp_claimed", "org") for e in physical)


# ---------------------------------------------------------------------------
# crossing
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def crossed(profile, derived, threats):
    controls_doc = {"controls": derived["controls"]}
    resp_doc = classify_resp.classify(profile, derived["controls"])
    return merge.cross(controls_doc, resp_doc, threats)


def test_threat_only_bucket_is_populated(crossed):
    """The whole premise. An empty bucket means a generic threat model, and the
    tool has degraded into a baseline filter."""
    assert crossed["counts"]["threat_only"] >= 3


def test_service_specific_threats_raise_priority(crossed):
    item = next(i for i in crossed["items"] if i["control"] == "AC-3")
    assert item["origin"] == "threat_and_baseline"
    assert item["priority"] == "high"


def test_generic_threat_does_not_raise_to_high(crossed):
    """SC-8 rather than AC-7. AC-7 carried this property until the profile's
    declared organisational controls started being applied -- the golden profile
    runs company-wide SSO, so AC-7 is the organisation's and its priority drops
    accordingly. The property being tested is about threats, not about who owns
    the control, so the test needed a control the org controls do not reach."""
    item = next(i for i in crossed["items"] if i["control"] == "SC-8")
    assert item["origin"] == "threat_and_baseline"
    assert item["priority"] == "medium"


def test_a_declared_capability_discharges_only_what_it_performs():
    """The first version of this moved every covered control to the
    organisation, which deleted work that genuinely exists.

    Asserted per declaration rather than by asking the source what it did:
    a test that selects whatever the code annotated and checks the code moved
    it cannot notice an over-broad mapping, which is what it was hiding.
    """
    def owners(declared, controls, csp="aws"):
        p = _onprem()
        p["inferred"]["csp"] = csp
        p["declared"]["existing_org_controls"] = declared
        result = classify_resp.classify(p, controls)
        return {e["control"]: e["responsibility"] for e in result["controls"]}

    # SSO performs identification and authentication. It does not perform
    # account lifecycle, unsuccessful-logon enforcement, or session termination.
    sso = owners(["company-wide SSO / identity provider"],
                 ["IA-2", "AC-2", "AC-7", "AC-12"])
    assert sso["IA-2"] == "org"
    assert sso["AC-2"] == "team" and sso["AC-7"] == "team" and sso["AC-12"] == "team"

    # A shared control keeps its team half. An organisational capability answers
    # the organisation's side of a division, not both sides of it.
    logging = owners(["centralised log collection"], ["AU-6", "AU-6(1)", "AU-9"])
    assert logging["AU-6"] == "org"
    assert logging["AU-6(1)"] == "shared", "the team half of a shared control survives"
    assert logging["AU-9"] == "shared", "protecting the application's own audit records"

    # An incident process is the incident controls, not the system's response to
    # an audit processing failure.
    incident = owners(["incident response process"], ["IR-4", "AU-5"])
    assert incident["IR-4"] == "org"
    assert incident["AU-5"] != "org" or "AU-5" not in classify_resp.ORG_CONTROL_COVERAGE.get(
        "incident_response", [])

    # A standing security function is the role PM-2 asks for. It does not write
    # the programme plan or lead risk management.
    assert set(classify_resp.ORG_CONTROL_COVERAGE["security_function"]) == {"PM-2"}


def test_a_shared_control_is_not_reclassified_on_a_profile_with_no_provider():
    """Reassignment ran before the rule that gives an ownerless shared
    responsibility back to the team, so a covered shared control on an
    on-premise profile escaped it and landed on nobody."""
    p = _onprem()
    p["declared"]["existing_org_controls"] = ["centralised log collection"]
    result = classify_resp.classify(p, ["AU-6(1)"])
    entry = result["controls"][0]
    # shared collapses to team when there is no second party, and the covered
    # control now reaches that rule instead of being moved past it.
    assert entry["responsibility"] == "team"
    assert "no-csp" in entry["source"]


@pytest.mark.parametrize("written", ["AC-3", "ac-3", " AC-3 ", "Ac-3"])
def test_related_control_spelling_does_not_fabricate_a_finding(written):
    """`threat_only` is the tool's central claim: a risk no baseline control
    addresses. A mistyped identifier produced exactly that outcome, so a
    spelling slip manufactured a finding while losing the priority raise on the
    control that was meant. The two were indistinguishable."""
    controls = {"controls": ["AC-3"], "forced_requirements": []}
    resp = {"controls": [{"control": "AC-3", "responsibility": "team", "services": []}]}
    threats = {"threats": [{"id": "T-1", "novelty": "service_specific",
                            "related_controls": [written]}]}
    result = merge.cross(controls, resp, threats)
    assert result["counts"].get("threat_and_baseline") == 1
    assert not result["counts"].get("threat_only")
    assert result["problems"] == []


def test_oscal_dotted_identifier_resolves():
    """`ac-3.1` is the identifier in the bundled records, so it is what someone
    reading them copies; `AC-3(1)` is what the catalog is keyed on."""
    controls = {"controls": ["AC-3(1)"], "forced_requirements": []}
    resp = {"controls": [{"control": "AC-3(1)", "responsibility": "team", "services": []}]}
    threats = {"threats": [{"id": "T-1", "related_controls": ["ac-3.1"]}]}
    assert merge.cross(controls, resp, threats)["counts"].get("threat_and_baseline") == 1


def test_an_unresolvable_reference_is_reported_not_promoted():
    """A control that does not exist must not silently become a threat-only
    finding -- the crossing runs before lint, so the false finding is already in
    the work list by the time anything checks identifiers."""
    controls = {"controls": ["AC-3"], "forced_requirements": []}
    resp = {"controls": [{"control": "AC-3", "responsibility": "team", "services": []}]}
    threats = {"threats": [{"id": "T-1", "related_controls": ["ZZ-9"]}]}
    result = merge.cross(controls, resp, threats)
    assert result["counts"].get("threat_only") == 1
    named = [p for p in result["problems"] if "ZZ-9" in p["message"]]
    assert named and named[0]["kind"] == "unresolved", \
        "a reference that matched no control is a different kind of problem from a schema slip"


@pytest.mark.parametrize("threats,message", [
    ({"threats": [{"related_controls": []}]}, "id"),
    ({"threats": ["T-1"]}, "mapping"),
])
def test_malformed_threat_records_say_what_is_wrong(threats, message):
    controls = {"controls": ["AC-3"], "forced_requirements": []}
    resp = {"controls": [{"control": "AC-3", "responsibility": "team", "services": []}]}
    with pytest.raises(ValueError, match=message):
        merge.cross(controls, resp, threats)


def test_unmatched_baseline_controls_are_retained(crossed):
    """Coverage is the baseline's contribution. Dropping these loses the ability
    to answer "why is this family absent?"."""
    assert crossed["counts"]["baseline_only"] > 0


# ---------------------------------------------------------------------------
# merge
# ---------------------------------------------------------------------------

@pytest.fixture()
def draft():
    return json.loads((GOLDEN / "draft.json").read_text(encoding="utf-8"))["requirements"]


def test_identifiers_are_stable_across_reruns(draft):
    state = {"issued": {}}
    first = merge.apply_merge(draft, [], state)
    ids_first = {r["id"] for r in first["requirements"]}

    # A requirement is inserted ahead of the others on the next run.
    inserted = [{"slug": "NEW-TOPIC", "managed": {"statement": "x"}}] + draft
    second = merge.apply_merge(inserted, first["requirements"], state)
    ids_second = {r["id"] for r in second["requirements"]}

    assert ids_first <= ids_second, "existing identifiers must survive an insertion"


def test_human_edits_are_never_overwritten(draft):
    state = {"issued": {}}
    result = merge.apply_merge(draft, [], state)
    existing = result["requirements"]

    target = next(r for r in existing if r["id"] == "REQ-TENANT-ISOLATION-01")
    target["human"] = {
        "status": "exception",
        "exception": {"approver": "CISO", "expires": "2026-12-31", "reason": "cost"},
    }

    changed = copy.deepcopy(draft)
    for item in changed:
        if item["slug"] == "TENANT-ISOLATION":
            item["managed"]["statement"] = "A completely rewritten statement."

    second = merge.apply_merge(changed, existing, state)
    updated = next(r for r in second["requirements"] if r["id"] == "REQ-TENANT-ISOLATION-01")

    assert updated["human"]["exception"]["approver"] == "CISO"
    assert "A completely rewritten" not in updated["managed"]["statement"]
    assert updated["pending_review"]["managed"]["statement"].startswith("A completely rewritten")


def test_retirement_preserves_an_accepted_risk(draft):
    """Found by exercising refresh against a real requirement set.

    A requirement carrying an approved exception was retired by a re-derivation,
    and `status` was overwritten with `retired`. The approval record survived,
    but every report that asks "which risks are accepted and when do they
    expire?" queries `status == exception` -- so the accepted risk silently left
    that list while leaving behind an approval that contradicted the retirement.
    """
    state = {"issued": {}}
    first = merge.apply_merge(draft, [], state)
    existing = first["requirements"]

    slug = draft[0]["slug"]
    target_id = merge.issue_id(slug, state)
    next(r for r in existing if r["id"] == target_id)["human"] = {
        "status": "exception",
        "exception": {"approver": "CISO", "expires": "2026-12-31", "reason": "revisit next quarter"},
    }

    reduced = [item for item in draft if item["slug"] != slug]
    second = merge.apply_merge(reduced, existing, state)
    retired = next(r for r in second["requirements"] if r["id"] == target_id)

    assert retired["human"]["status"] == "retired"
    assert retired["human"]["previous_status"] == "exception"
    assert retired["human"]["exception"]["approver"] == "CISO"
    assert "CISO" in retired["human"]["retired_reason"]


def test_a_returning_requirement_is_reopened(draft):
    """A retired requirement that derives again is live work. Leaving it retired
    drops it on the floor; reinstating its exception silently would restore an
    accepted risk nobody re-approved."""
    state = {"issued": {}}
    first = merge.apply_merge(draft, [], state)
    existing = first["requirements"]
    slug = draft[0]["slug"]
    target_id = merge.issue_id(slug, state)
    next(r for r in existing if r["id"] == target_id)["human"] = {
        "status": "exception",
        "exception": {"approver": "CISO", "expires": "2026-12-31", "reason": "..."},
    }

    reduced = [item for item in draft if item["slug"] != slug]
    second = merge.apply_merge(reduced, existing, state)
    third = merge.apply_merge(draft, second["requirements"], state)

    assert target_id in third["reopened"]
    back = next(r for r in third["requirements"] if r["id"] == target_id)
    assert back["human"]["status"] == "active"
    assert back["human"]["exception"]["approver"] == "CISO"   # kept, for re-affirmation


def test_in_place_rewrite_is_reported_as_updated(draft):
    """Found by exercising refresh: a requirement whose text was replaced in
    place was counted in both `added` and `unchanged`, so the report described a
    silent rewrite as no change at all."""
    state = {"issued": {}}
    first = merge.apply_merge(draft, [], state)

    changed = copy.deepcopy(draft)
    changed[0]["managed"]["statement"] = "A completely different obligation."
    second = merge.apply_merge(changed, first["requirements"], state)

    target = merge.issue_id(draft[0]["slug"], state)
    assert target in second["updated"]
    assert target not in second["added"]
    assert target not in second["unchanged"]
    assert not (set(second["added"]) & set(second["unchanged"]))


def test_requirements_are_retired_not_deleted(draft):
    state = {"issued": {}}
    first = merge.apply_merge(draft, [], state)
    reduced = [item for item in draft if item["slug"] != "DB-TRANSPORT-TLS"]
    second = merge.apply_merge(reduced, first["requirements"], state)

    survivor = next(r for r in second["requirements"] if r["id"] == "REQ-DB-TRANSPORT-TLS-01")
    assert survivor["human"]["status"] == "retired"
    assert survivor["human"]["retired_reason"]


# ---------------------------------------------------------------------------
# lint
# ---------------------------------------------------------------------------

def _doc(**managed):
    base = {
        "statement": "Personal data at rest must be encrypted with a customer-managed key.",
        "sources": ["SC-28"],
        "threat_refs": ["T-01"],
        "responsibility": "team",
        # csf is carried because the linter requires it: without one the
        # requirement is filed as UNCLASSIFIED in the published document, and
        # the document's whole organising principle is the CSF function.
        "csf": ["PR.DS-01"],
        "verification": {"method": "iac_inspect", "expect": "encryption enabled"},
    }
    base.update(managed)
    return {"requirements": [{"id": "REQ-DATA-ENC-REST-01", "managed": base, "human": {}}]}


def _rules(findings):
    return {f.rule for f in findings}


def test_invented_identifier_is_blocked():
    findings = lint_mod.lint(_doc(sources=["SC-28(4)"]), "en", None)
    assert any(f.level == "ERROR" and f.rule == "source-unknown" for f in findings)


def test_invented_family_is_blocked_not_merely_warned():
    """Regression: an unknown family degraded to "not bundled yet" and survived."""
    findings = lint_mod.lint(_doc(sources=["ZZ-9"]), "en", None)
    assert any(f.level == "ERROR" and f.rule == "source-unknown" for f in findings)


def test_unbundled_family_is_a_warning_not_an_error():
    """All twenty families are bundled now, so this path only appears after a
    partial extraction. It still has to behave: a real family that is merely
    absent is a warning, an invented one is an error, and the two must not be
    confused."""
    findings = lint_mod.check_sources(
        "REQ-X-Y-01",
        ["CP-9"],
        catalog=set(),
        bundled={"AC", "AU", "SC"},
        known=lint_mod.known_families(),
    )
    assert [f for f in findings if f.rule == "source-unbundled" and f.level == "WARN"]

    invented = lint_mod.check_sources(
        "REQ-X-Y-01", ["ZZ-9"], catalog=set(), bundled={"AC"}, known=lint_mod.known_families()
    )
    assert [f for f in invented if f.level == "ERROR"]


def test_vague_statement_is_blocked():
    findings = lint_mod.lint(_doc(statement="Data must be appropriately protected at rest."), "en", None)
    assert any(f.level == "ERROR" and f.rule == "vague" for f in findings)


def test_missing_verification_is_blocked():
    doc = _doc()
    del doc["requirements"][0]["managed"]["verification"]
    assert "no-verification" in _rules(lint_mod.lint(doc, "en", None))


def test_inheritance_without_evidence_is_blocked():
    findings = lint_mod.lint(_doc(responsibility="csp_claimed"), "en", None)
    assert any(f.level == "ERROR" and f.rule == "no-evidence" for f in findings)


def test_threat_derived_requirement_may_cite_no_control():
    """Regression: threat-only requirements were flagged for having no source.

    Having no baseline control is what puts them in that bucket, and they are
    the findings the baseline could not produce.
    """
    findings = lint_mod.lint(_doc(sources=[], threat_refs=["T-03"]), "en", None)
    assert not any(f.rule in ("no-source", "no-basis") for f in findings)


def test_requirement_with_no_basis_at_all_is_flagged():
    findings = lint_mod.lint(_doc(sources=[], threat_refs=[]), "en", None)
    assert "no-basis" in _rules(findings)


@pytest.mark.parametrize("written", ["SC-28", "sc-28", " SC-28 ", "Sc-28"])
def test_control_identifier_spelling_is_accepted(written):
    """The question is whether the cited control exists, not whether it was
    typed in capitals. The profile loader canonicalises; this did not, so a
    lower-case citation failed the format check."""
    findings = lint_mod.lint(_doc(sources=[written]), "en", None)
    assert not [f for f in findings if f.level == "ERROR"]


@pytest.mark.parametrize("field,value", [("sources", "SC-28"), ("csf", "PR.DS-01")])
def test_a_scalar_identifier_field_says_so_once(field, value):
    """A string is iterable, so a scalar was checked character by character and
    produced one identical format error per letter. Five errors about 'S', 'C',
    and '-' do not tell the reader a pair of brackets is missing."""
    findings = lint_mod.lint(_doc(**{field: value}), "en", None)
    matching = [f for f in findings if f.rule == f"{field}-format"]
    assert len(matching) == 1
    assert "list" in matching[0].message


def test_verification_method_spelling_is_accepted():
    findings = lint_mod.lint(
        _doc(verification={"method": " IaC_Inspect ", "expect": "ok"}), "en", None)
    assert not [f for f in findings if f.rule == "verification-method"]


def test_invented_identifier_survives_canonicalisation():
    """Normalising spelling must not normalise away the integrity check."""
    findings = lint_mod.lint(_doc(sources=["sc-28(4)"]), "en", None)
    assert any(f.level == "ERROR" and f.rule == "source-unknown" for f in findings)


def test_invented_asvs_identifier_is_blocked():
    findings = lint_mod.lint(_doc(sources=["ASVS-V6.9.9"]), "en", None)
    assert any(f.level == "ERROR" and f.rule == "source-unknown" for f in findings)


def test_real_asvs_identifier_passes():
    assert "ASVS-V1.1.1" in lint_mod.load_ids(lint_mod.ASVS_DIR)
    findings = lint_mod.lint(_doc(sources=["ASVS-V1.1.1"]), "en", None)
    assert not [f for f in findings if f.level == "ERROR"]


def test_invented_csf_subcategory_is_blocked():
    findings = lint_mod.lint(_doc(csf=["PR.ZZ-99"]), "en", None)
    assert any(f.level == "ERROR" and f.rule == "csf-unknown" for f in findings)


def test_real_csf_subcategory_passes():
    findings = lint_mod.lint(_doc(csf=["PR.DS-01"]), "en", None)
    assert not [f for f in findings if f.level == "ERROR"]


def test_verification_method_is_a_closed_set():
    """"Verify it somehow" is not a method, and v2 automation dispatches on
    this value."""
    findings = lint_mod.lint(
        _doc(verification={"method": "wave_hands", "expect": "ok"}), "en", None
    )
    assert any(f.level == "ERROR" and f.rule == "verification-method" for f in findings)


def test_golden_fixture_passes_lint():
    doc = {"requirements": [
        {"id": merge.issue_id(item["slug"], {"issued": {}}), "managed": item["managed"], "human": {}}
        for item in json.loads((GOLDEN / "draft.json").read_text(encoding="utf-8"))["requirements"]
    ]}
    findings = lint_mod.lint(doc, "en", yaml.safe_load((GOLDEN / "threats.yaml").read_text(encoding="utf-8")))
    errors = [f for f in findings if f.level == "ERROR"]
    assert not errors, [str(f) for f in errors]


# ---------------------------------------------------------------------------
# rendering and scoring
# ---------------------------------------------------------------------------

import render as render_mod  # noqa: E402
import eval_golden as eval_mod  # noqa: E402


def _rendered_req(**managed):
    base = {"statement": "X must be Y.", "csf": ["PR.DS-01"], "sources": ["SC-28"],
            "responsibility": "team", "priority": "high",
            "verification": {"method": "manual", "expect": "ok"}}
    base.update(managed)
    return {"id": "REQ-A-B-01", "managed": base, "human": {}}


@pytest.mark.parametrize("csf", ["PR.DS-01", ["PR.DS-01"], ["pr.ds-01"], [" PR.DS-01 "]])
def test_csf_spelling_files_under_the_right_function(csf):
    """A scalar indexed to the character "P", so the requirement dropped out of
    PROTECT into the unclassified bin at the foot of the document -- a silent
    misfiling, invisible unless someone counts."""
    assert render_mod.function_of(_rendered_req(csf=csf)) == "PR"


@pytest.mark.parametrize("status", ["retired", "RETIRED", " Retired ", "superseded"])
def test_retired_requirements_stay_out_of_the_document(status):
    """The status comparison was case-sensitive, so `RETIRED` read as active and
    a requirement someone had deliberately retired reappeared as live work."""
    req = _rendered_req()
    req["human"] = {"status": status}
    assert render_mod.active(req) is False


def test_scalar_match_any_is_refused():
    """It iterated to characters, so a topic matched whenever the statement
    contained the letter "t". A suite reporting coverage it does not have is
    worse than no suite."""
    doc = {"requirements": [
        {"id": "R", "managed": {"statement": "Audit logs must be immutable."}, "human": {}}]}
    topic = {"id": "tenant", "must_cover": True, "match_any": "tenant", "description": "d"}
    with pytest.raises(ValueError, match="list of hints"):
        eval_mod.score({"topics": [topic], "scoring": {}}, doc)


def test_topic_without_hints_is_refused():
    doc = {"requirements": []}
    topic = {"id": "t", "must_cover": True, "description": "d"}
    with pytest.raises(ValueError, match="match_any"):
        eval_mod.score({"topics": [topic], "scoring": {}}, doc)


# ---------------------------------------------------------------------------
# inheritance, service identity, and catalog provenance
# ---------------------------------------------------------------------------

def test_a_backup_of_secrets_is_not_low(profile):
    """Found by probing inherit_max chains.

    Excluding system information from the water mark leaked into the
    inheritance pool, so a store holding nothing but credentials derived Low.
    What a backup contains and how a system is categorised are different
    questions.
    """
    p = copy.deepcopy(profile)
    p["declared"]["data_types"] = [{"id": "backups"}, {"id": "config_secrets"}]
    reasons = sb.run(p)["impact"]["confidentiality"]["because"]
    backup = next(r for r in reasons if "backup" in r.lower())
    assert backup.endswith("high")
    assert "system information" in backup


def test_a_backup_cannot_launder_credentials_into_the_water_mark(profile):
    """The other half of the same rule. Feeding the inherited level back into
    categorisation would let credentials reach the system level through a
    backup and defeat their exclusion."""
    p = copy.deepcopy(profile)
    p["declared"]["data_types"] = [
        {"id": "backups"}, {"id": "config_secrets"}, {"id": "internal_ops"},
    ]
    assert sb.run(p)["impact"]["system"] == "moderate"


@pytest.mark.parametrize("written", ["aws-s3", "AWS-S3", "aws-S3", " aws-s3 ", "Aws-S3"])
def test_service_identifier_spelling_resolves_the_same_everywhere(profile, written):
    """Service identifiers become filenames. Left as written, `AWS-S3` found the
    curated file on a case-insensitive filesystem and nothing on a
    case-sensitive one, so the same profile produced different responsibility
    splits on macOS and on Linux."""
    p = copy.deepcopy(profile)
    p["inferred"]["managed_services"] = [{"id": written}]
    result = classify_resp.classify(p, ["SC-28"])
    assert result["services_curated"] == ["aws-s3"]
    assert result["services_uncurated"] == []


def test_duplicate_services_are_declared_once(profile):
    p = copy.deepcopy(profile)
    p["inferred"]["managed_services"] = [{"id": "aws-s3"}, "aws-s3", {"id": "AWS-S3"}]
    assert classify_resp.classify(p, ["SC-28"])["services_curated"] == ["aws-s3"]


def test_catalog_provenance_records_what_is_on_disk():
    """A partial rebuild writes the families it was asked for and leaves the
    rest where an earlier run put them, so the directory can hold two builds
    while the provenance names one. Consumers read the directory."""
    meta = json.loads(
        (REPO_ROOT / "catalogs" / "nist-800-53r5" / "meta.json").read_text(encoding="utf-8"))
    assert meta["families_present"] == meta["families_extracted"]
    assert meta["families_stale"] == []


# ---------------------------------------------------------------------------
# regulatory overlays
# ---------------------------------------------------------------------------

import apply_overlay as overlay_mod  # noqa: E402


ALL_OVERLAYS = ["pipa-isms-p", "hipaa-security-rule", "gdpr", "pci-dss", "soc2", "iso-27001"]


@pytest.mark.parametrize("overlay_id", ALL_OVERLAYS)
def test_overlay_cites_only_controls_that_exist(overlay_id):
    """The mappings are authored, not published. An overlay citing a control
    that does not exist would launder a fabricated identifier into the
    deliverable through a side door the catalog check does not watch."""
    loaded = overlay_mod.load(overlay_id)
    cited = {c for m in loaded["mappings"] for c in m["controls"]}
    assert cited
    assert cited <= overlay_mod.catalog_ids()


@pytest.mark.parametrize("overlay_id", ALL_OVERLAYS)
def test_overlay_maps_every_clause_it_bundles(overlay_id):
    loaded = overlay_mod.load(overlay_id)
    assert {m["clause"] for m in loaded["mappings"]} == set(loaded["criteria"])


@pytest.mark.parametrize("overlay_id", ALL_OVERLAYS)
def test_overlay_states_that_its_mapping_is_authored(overlay_id):
    """Presenting an authored reading as a published crosswalk is the failure
    this repository exists to avoid."""
    meta = overlay_mod.load(overlay_id)["meta"]
    assert meta["mapping"]["authored"] is True
    assert meta["disclaimer"].strip()


def test_overlay_covers_every_clause_it_bundles():
    loaded = overlay_mod.load("pipa-isms-p")
    assert len(loaded["criteria"]) == 101
    assert {m["clause"] for m in loaded["mappings"]} == set(loaded["criteria"])


def test_overlay_matches_the_published_structure():
    """16 / 64 / 21 across the three areas is the 2023.11.23 revision, which
    removed the dormant-account clause. A different shape means the source
    drifted."""
    loaded = overlay_mod.load("pipa-isms-p")
    counts = {}
    for c in loaded["criteria"].values():
        counts[c["area"]] = counts.get(c["area"], 0) + 1
    assert sorted(counts.values()) == [16, 21, 64]


def test_overlay_excludes_the_copyrighted_guide():
    """The criteria are a schedule to a ministerial notice and fall outside
    copyright. The KISA guide's 주요 확인사항 and 세부설명 do not, and must not
    be carried over."""
    loaded = overlay_mod.load("pipa-isms-p")
    fields = {k for c in loaded["criteria"].values() for k in c}
    assert fields == {"clause", "title", "area", "domain", "statement"}


def test_scope_follows_whether_personal_data_is_processed(profile):
    """ISMS-P has two certification scopes. Gating the whole overlay on personal
    data was wrong: a service holding none can still be ISMS-certified against
    the first eighty clauses."""
    loaded = overlay_mod.load("pipa-isms-p")

    without = copy.deepcopy(profile)
    without["declared"]["user_regions"] = ["KR"]
    without["declared"]["data_types"] = [{"id": "internal_ops"}]
    ok, _, scope = overlay_mod.applies(loaded, without)
    assert ok and scope["scope"] == "ISMS"
    assert overlay_mod.evaluate(loaded, [], scope)["clause_count"] == 80

    with_pd = copy.deepcopy(without)
    with_pd["declared"]["data_types"] = [{"id": "basic_contact"}]
    ok, _, scope = overlay_mod.applies(loaded, with_pd)
    assert ok and scope["scope"] == "ISMS-P"
    assert overlay_mod.evaluate(loaded, [], scope)["clause_count"] == 101


def test_overlay_does_not_apply_outside_its_jurisdiction(profile):
    loaded = overlay_mod.load("pipa-isms-p")
    elsewhere = copy.deepcopy(profile)
    elsewhere["declared"]["user_regions"] = ["DE"]
    ok, reason, _ = overlay_mod.applies(loaded, elsewhere)
    assert ok is False and "KR" in reason


def test_clauses_no_control_expresses_are_named(derived):
    """These are the overlay's reason to exist: the clauses an audit asks about
    that a 800-53 derivation cannot produce."""
    loaded = overlay_mod.load("pipa-isms-p")
    result = overlay_mod.evaluate(loaded, derived["controls"], {"scope": "ISMS-P", "areas": None})
    standalone = {row["clause"] for row in result["standalone"]}
    assert "3.3.4" in standalone      # cross-border transfer
    assert "3.1.3" in standalone      # resident registration number
    assert all(row["notes"] for row in result["standalone"])


def test_a_regulation_with_an_overlay_is_no_longer_declared_uncovered(profile):
    """Leaving PIPA in the uncovered list after building its overlay would keep
    declaring a gap the repository has closed. Regulations without one must
    still be declared."""
    p = copy.deepcopy(profile)
    p["declared"]["user_regions"] = ["US"]
    p["declared"]["data_types"] = [{"id": "basic_contact"}, {"id": "minors_data"}]
    result = sb.run(p)

    assert "hipaa-security-rule" not in result["applicable_overlays"]   # no health data
    uncovered = {t["id"] for t in result["uncovered_regulations"]}
    # COPPA has no overlay, so it is still declared rather than silently dropped.
    assert "coppa" in uncovered


def test_hipaa_matches_the_published_rule_shape():
    """Nine administrative standards, four physical, five technical. The
    extractor asserts this too; the test guards the committed artefact."""
    src = json.loads(
        (REPO_ROOT / "overlays" / "hipaa-security-rule" / "source.json").read_text(encoding="utf-8"))
    assert src["standards_per_section"] == {
        "164.308": 9, "164.310": 4, "164.312": 5, "164.314": 2, "164.316": 2}
    assert src["designations"] == {"Required": 24, "Addressable": 22}


def test_addressable_specifications_are_carried():
    """Addressable is not optional -- where it is not implemented the rule
    requires a documented reason and an equivalent measure. Dropping the
    addressable half would understate the obligation by nearly half."""
    loaded = overlay_mod.load("hipaa-security-rule")
    designations = {c.get("designation") for c in loaded["criteria"].values()}
    assert "Addressable" in designations and "Required" in designations


def test_an_overlay_without_scopes_does_not_borrow_anothers(profile):
    """Found on the second overlay. `applies()` defaulted to the ISMS-P scope
    selector, so a US health regulation was reported as certifying at a Korean
    scope: one overlay's vocabulary leaked into another."""
    loaded = overlay_mod.load("hipaa-security-rule")
    p = copy.deepcopy(profile)
    p["declared"]["user_regions"] = ["US"]
    p["declared"]["data_types"] = [{"id": "health_records"}]
    ok, reason, scope = overlay_mod.applies(loaded, p)
    assert ok and scope["scope"] == "full"
    assert "ISMS" not in reason


def test_hipaa_does_not_apply_without_health_data(profile):
    loaded = overlay_mod.load("hipaa-security-rule")
    p = copy.deepcopy(profile)
    p["declared"]["user_regions"] = ["US"]
    p["declared"]["data_types"] = [{"id": "basic_contact"}]
    ok, reason, _ = overlay_mod.applies(loaded, p)
    assert ok is False and "data type" in reason


def test_hipaa_trigger_routes_to_its_overlay(profile):
    p = copy.deepcopy(profile)
    p["declared"]["user_regions"] = ["US"]
    p["declared"]["data_types"] = [{"id": "health_records"}]
    result = sb.run(p)
    assert "hipaa-security-rule" in result["applicable_overlays"]
    assert "hipaa" not in {t["id"] for t in result["uncovered_regulations"]}


def test_privacy_baseline_is_resolved_for_personal_data(profile):
    """Found by building the GDPR overlay.

    SP 800-53B allocates the privacy controls to a privacy baseline, which this
    repository bundled from the start and never resolved -- the derivation only
    ever produced low, moderate, or high, all security baselines. Ten GDPR
    articles therefore landed outside the derived set, not because nothing
    addresses them but because the controls that do live in a baseline nothing
    was reading.
    """
    result = sb.run(profile)
    assert result["privacy_baseline_applies"] is True
    assert len(result["privacy_controls"]) > 50
    assert "PT-4" in result["privacy_controls"]

    no_personal = copy.deepcopy(profile)
    no_personal["declared"]["data_types"] = [{"id": "internal_ops"}]
    assert sb.run(no_personal)["privacy_baseline_applies"] is False


def test_the_derivation_carries_every_layer_it_selected(profile):
    """Judging a privacy regime against the security baseline alone reports the
    tool's own blind spot as the service's gap.

    The first version of this test passed the privacy set to the overlay by
    hand, which proved the overlay could use it and hid the fact that nothing
    else did. The derivation computed the privacy and programme layers, printed
    their sizes, and then published the impact baseline alone -- so the whole PT
    family reached no responsibility split, no merge, and no overlay. What has
    to hold is that the derived list itself carries them.
    """
    derived = sb.run(profile)
    controls = set(derived["controls"])
    assert set(derived["privacy_controls"]) <= controls
    assert set(derived["program_controls"]) <= controls
    assert any(c.startswith("PT-") for c in controls), \
        "the privacy families must reach the derived list, not just its console summary"

    # And the count must keep naming what it names: the impact baseline it was
    # always the size of, not the union it now sits beside.
    baselines = json.loads((REPO_ROOT / "catalogs" / "nist-800-53r5" /
                            "baselines.json").read_text(encoding="utf-8"))
    impact = set(baselines[derived["baseline"].replace("nist-800-53b-", "")])
    assert derived["control_count"] == len(impact) - len(derived["controls_unavailable"])
    assert derived["control_count"] < len(derived["controls"])


def test_broad_coverage_is_reported_as_uninformative(profile):
    """A count that approaches the total has stopped discriminating.

    With the privacy and programme layers reaching the derivation, HIPAA reads
    68 of 68 and ISO 11 of 11. Both are true under the definition of "reached"
    -- every mapped control was selected -- and both read as compliance to any
    person who sees them. A disclaimer at the foot of the page does not survive
    a number like that, so the saturation is stated where the number is.
    """
    derived = sb.run(profile)
    result = overlay_mod.evaluate(overlay_mod.load("hipaa-security-rule"),
                                  derived["controls"], profile=profile)
    assert len(result["covered"]) / result["clause_count"] >= 0.85
    rendered = overlay_mod.render(result, "test")
    assert "carry no information about the service" in rendered
    assert "fully covered" not in rendered

    # The warning has to precede the number it warns about. The first version
    # said "READ THIS BEFORE THE NUMBERS ABOVE" from below them.
    lines = rendered.splitlines()
    warning_at = next(i for i, l in enumerate(lines) if "Before the counts" in l)
    count_at = next(i for i, l in enumerate(lines) if "reached by the derived" in l)
    assert warning_at < count_at


def test_clauses_no_delivery_team_control_touches_are_named(profile):
    """What restores the discrimination the headline count lost.

    A clause reached only through PM-1 and PS-3 is not a clause this repository
    can close, and saying so is worth more than the count it sits under.
    """
    derived = sb.run(profile)
    result = overlay_mod.evaluate(overlay_mod.load("hipaa-security-rule"),
                                  derived["controls"], profile=profile)
    org_only = {row["clause"] for row in result["org_only"]}
    assert org_only, "some administrative safeguards must land outside the team's reach"
    assert org_only <= {row["clause"] for row in result["covered"] + result["partial"]}
    assert "164.308(a)(2)" in org_only     # assigned security responsibility
    assert "no control in this" in overlay_mod.render(result, "test")


def test_a_shared_obligation_is_not_reported_as_untouchable(profile):
    """The tool contradicting itself on the same page.

    Three clauses carry a responsibility_note saying the regime treats the
    obligation as shared and naming the team's half -- producing everything held
    about one person, propagating an erasure to each recipient. Every control
    mapped to them is the organisation's, so they land in org_only, and the
    report said "nothing the delivery team builds touches them" directly beneath
    a mapping that says the opposite.

    The note never arrived because the row was assembled from four hand-picked
    mapping fields. The row is the mapping now, so the next field added to the
    files reaches the report without anyone remembering to carry it.
    """
    eu = copy.deepcopy(profile)
    eu["declared"]["user_regions"] = ["DE"]
    eu["declared"]["data_types"] = [{"id": "basic_contact"}, {"id": "audit_logs"}]
    derived = sb.run(eu)
    result = overlay_mod.evaluate(overlay_mod.load("gdpr"), derived["controls"], profile=eu)

    rows = {row["clause"]: row for row in result["org_only"]}
    assert "Art. 15" in rows, "the right of access is reached only by organisational controls"
    assert rows["Art. 15"]["responsibility_hint"] == "shared"
    assert (rows["Art. 15"].get("responsibility_note") or "").strip(), \
        "the mapping's note must survive into the evaluated row"

    rendered = overlay_mod.render(result, "test")
    assert "the team's half is not" in rendered
    assert "producing everything held about one" in rendered


def test_gdpr_is_mostly_unmappable_and_that_is_the_finding():
    """The proportion is a property of the regime. HIPAA's Security Rule reads
    like a control catalogue and has no standalone clauses; the Regulation is
    largely obligations on what a system must be able to do and prove."""
    gdpr = overlay_mod.load("gdpr")
    hipaa = overlay_mod.load("hipaa-security-rule")
    gdpr_standalone = sum(1 for m in gdpr["mappings"] if m["standalone"])
    assert gdpr_standalone > len(gdpr["mappings"]) // 3
    assert sum(1 for m in hipaa["mappings"] if m["standalone"]) == 0


def test_gdpr_scope_excludes_the_non_operative_chapters():
    """Chapters I and VI to XI establish scope, supervisory machinery, and final
    provisions. Fifty clauses saying "not applicable to system design" is
    padding, not coverage."""
    loaded = overlay_mod.load("gdpr")
    chapters = {c["chapter"] for c in loaded["criteria"].values()}
    assert chapters == {"II", "III", "IV", "V"}
    assert len(loaded["criteria"]) == 46


def test_pci_reproduces_no_standard_text():
    """PCI SSC licenses the standard under terms that forbid redistribution.
    Requirement numbers are identifiers; the descriptions must be this
    repository's own."""
    loaded = overlay_mod.load("pci-dss")
    meta = loaded["meta"]
    assert meta["source"]["bundled"] is False
    for c in loaded["criteria"].values():
        assert "statement" not in c          # no clause text carried
        assert c["scope_description"]
        assert c["text_source"].startswith("https://www.pcisecuritystandards.org")


def test_pci_declares_its_depth():
    """Stopping above the clause a reader is assessed against is a limitation
    that has to be stated, not a detail."""
    depth = overlay_mod.load("pci-dss")["meta"]["depth"]
    assert depth["sub_requirements_enumerated"] is False
    assert depth["level"]


def test_a_coarse_overlay_qualifies_its_coverage_count(profile):
    """"11 of 12 covered" is the single most dangerous line this tool can print
    for a regime assessed at the sub-requirement level."""
    loaded = overlay_mod.load("pci-dss")
    derived = sb.run(profile)
    result = overlay_mod.evaluate(loaded, derived["controls"])
    rendered = overlay_mod.render(result, "test")
    assert "DEPTH" in rendered
    assert "not whether any requirement is met" in rendered
    assert "fully covered" not in rendered

    deep = overlay_mod.evaluate(overlay_mod.load("gdpr"), derived["controls"])
    assert "DEPTH" not in overlay_mod.render(deep, "test")


def test_pci_scope_follows_whether_the_pan_is_stored(profile):
    """Whether the primary account number enters the system is the first
    question PCI asks and the one that changes everything."""
    loaded = overlay_mod.load("pci-dss")

    raw = copy.deepcopy(profile)
    raw["declared"]["data_types"] = [{"id": "payment_card_raw"}]
    ok, _, scope = overlay_mod.applies(loaded, raw)
    assert ok and scope["scope"] == "cardholder data environment"

    tokenised = copy.deepcopy(profile)
    tokenised["declared"]["data_types"] = [{"id": "payment_token"}]
    ok, _, scope = overlay_mod.applies(loaded, tokenised)
    assert ok and scope["scope"] == "reduced (tokenised)"

    none = copy.deepcopy(profile)
    none["declared"]["data_types"] = [{"id": "internal_ops"}]
    assert overlay_mod.applies(loaded, none)[0] is False


def test_tokenised_payments_still_raise_pci(profile):
    """Tokenisation reduces scope; it does not remove the standard. A profile
    that touches payments at all should be told so."""
    p = copy.deepcopy(profile)
    p["declared"]["data_types"] = [{"id": "payment_token", "modifiers": ["tokenized_external"]}]
    assert "pci-dss" in sb.run(p)["applicable_overlays"]


def test_soc2_reproduces_no_criteria_text():
    """The Trust Services Criteria are an AICPA copyrighted work. Series
    identifiers are identifiers; the descriptions must be this repository's."""
    loaded = overlay_mod.load("soc2")
    assert loaded["meta"]["source"]["bundled"] is False
    for c in loaded["criteria"].values():
        assert "statement" not in c
        assert c["scope_description"]


def test_soc2_categories_follow_the_profile(profile):
    """Security is mandatory and the other four categories are elective. What a
    profile records is a reasonable indication of which a service organisation
    would need to commit to."""
    loaded = overlay_mod.load("soc2")

    lean = copy.deepcopy(profile)
    lean["declared"]["regulations_declared"] = ["SOC 2 Type II"]
    lean["declared"]["data_types"] = [{"id": "internal_ops"}]
    lean["declared"]["availability"] = {
        "rto": "rto_day_plus", "rpo": "rpo_hours_plus", "amplifiers": ["internal_tool_only"]}
    ok, reason, scope = overlay_mod.applies(loaded, lean, sb.run(lean))
    assert ok and scope["areas"] == ["CC"]
    assert "no elective category" in reason

    broad = copy.deepcopy(profile)
    broad["declared"]["regulations_declared"] = ["SOC 2 Type II"]
    broad["declared"]["data_types"] = [{"id": "health_records"}, {"id": "basic_contact"}]
    broad["declared"]["availability"] = {
        "rto": "rto_minutes", "rpo": "rpo_zero", "amplifiers": ["safety_critical"]}
    _, _, scope = overlay_mod.applies(loaded, broad, sb.run(broad))
    assert set(scope["areas"]) == {"CC", "A1", "PI1", "C1", "P"}


def test_soc2_without_a_derivation_keeps_every_category(profile):
    """Narrowing scope on missing information would understate the
    examination."""
    loaded = overlay_mod.load("soc2")
    asked = copy.deepcopy(profile)
    asked["declared"]["regulations_declared"] = ["SOC 2"]
    ok, reason, scope = overlay_mod.applies(loaded, asked, None)
    assert ok and len(scope["areas"]) == 5
    assert "no derivation supplied" in reason


def test_elective_categories_filter_the_clause_set(profile):
    loaded = overlay_mod.load("soc2")
    derived = sb.run(profile)
    common_only = overlay_mod.evaluate(loaded, derived["controls"], {"scope": "CC", "areas": ["CC"]})
    everything = overlay_mod.evaluate(loaded, derived["controls"], {"scope": "all", "areas": None})
    assert common_only["clause_count"] == 9
    assert everything["clause_count"] == 13


def test_a_shallow_overlay_gives_its_own_reason(profile):
    """PCI's numbering is part of a licensed standard; SOC 2 additionally has no
    fixed control set to derive against. The renderer must not flatten both into
    one generic sentence."""
    derived = sb.run(profile)
    rendered = {}
    for overlay_id in ("pci-dss", "soc2"):
        loaded = overlay_mod.load(overlay_id)
        rendered[overlay_id] = overlay_mod.render(
            overlay_mod.evaluate(loaded, derived["controls"]), "test")
    assert "licence rather than effort" in rendered["pci-dss"]
    assert "service organisation writes for itself" in rendered["soc2"]


@pytest.mark.parametrize("overlay_id,alias", [("soc2", "SOC 2 Type II"), ("iso-27001", "ISO 27001")])
def test_elective_overlays_wait_to_be_asked_for(profile, overlay_id, alias):
    """Found while building the sixth overlay. Nothing in the data triggers a
    SOC 2 examination or ISO certification -- an organisation chooses them -- so
    an overlay with no applicability condition applied to every profile."""
    loaded = overlay_mod.load(overlay_id)

    silent = copy.deepcopy(profile)
    silent["declared"]["regulations_declared"] = []
    ok, reason, _ = overlay_mod.applies(loaded, silent)
    assert ok is False and "elective" in reason

    asked = copy.deepcopy(profile)
    asked["declared"]["regulations_declared"] = [f"{alias} required by our customers"]
    assert overlay_mod.applies(loaded, asked)[0] is True


def test_iso_reproduces_no_standard_text():
    loaded = overlay_mod.load("iso-27001")
    assert loaded["meta"]["source"]["bundled"] is False
    for c in loaded["criteria"].values():
        assert "statement" not in c
        assert c["scope_description"]


def test_iso_states_what_is_actually_certified(profile):
    """Certification is against clauses 4-10; Annex A is a reference set. A
    derivation works almost entirely in Annex A territory, and a reader who does
    not know that will misread every count."""
    loaded = overlay_mod.load("iso-27001")
    assert "clauses 4 to 10" in loaded["meta"]["framing"]

    derived = sb.run(profile)
    rendered = overlay_mod.render(overlay_mod.evaluate(loaded, derived["controls"]), "test")
    assert "Statement of Applicability" in rendered
    assert rendered.index("Certification is against") < rendered.index("reached by the derived")


def test_management_system_clauses_are_outside_the_delivery_teams_reach(profile):
    """A derivation does not build a management system.

    This used to be visible as ISO's clauses reporting unreached, because the PM
    family sat in no baseline the tool resolved. That was a gap in the tool
    standing in for a true statement -- and when the programme layer was added
    the clauses flipped to reached, which said the opposite. The finding is
    unchanged and now has to be asserted where it actually lives: every ISO
    management-system clause is reached only through controls the organisation
    owns.
    """
    loaded = overlay_mod.load("iso-27001")
    derived = sb.run(profile)
    result = overlay_mod.evaluate(loaded, derived["controls"])
    org_only = {r["clause"] for r in result["org_only"]}
    clauses = {r["clause"] for r in result["covered"] + result["partial"] + result["uncovered"]
               if r["clause"].startswith("Clause")}
    assert clauses, "the management-system clauses must be present"

    # Context, leadership, planning, support, and improvement: nothing a
    # delivery team builds reaches any of them.
    assert {"Clause 4", "Clause 5", "Clause 6", "Clause 7", "Clause 10"} <= org_only

    # Operation and performance evaluation are the two that are not, and the
    # reason is worth keeping: both are reached partly through CA-7, continuous
    # monitoring, which genuinely has a team half. Asserting all seven would
    # have been a tidier line and a false one.
    assert not ({"Clause 8", "Clause 9"} & org_only)
    assert "CA-7" in {c for r in result["covered"] + result["partial"]
                      if r["clause"] in ("Clause 8", "Clause 9") for c in r["controls"]}


def test_overlays_pass_the_validator():
    """Six overlays were added in succession and each found a defect in
    machinery written for the one before it. The structural checks run at load;
    these are the ones needing a view across overlays and against the
    baselines."""
    import subprocess
    r = subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "validate_overlays.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_unreachable_clauses_are_not_reported_as_gaps(profile):
    """A clause the tool cannot reach must not sit in the reader's gap list.

    The five real cases were all PM controls -- a security programme plan, a
    designated officer, risk-management leadership -- which SP 800-53B assigns
    to no impact baseline because the family is implemented once for the
    organisation. Those are now resolved as a programme layer, so the bucket is
    empty against the shipped overlays and the mechanism has to be exercised
    directly. It still matters: any future mapping may cite a control that no
    baseline selects, and the difference between "this service has not done it"
    and "this tool cannot see it" is the difference between a finding and a
    defect.
    """
    derived = sb.run(profile)
    loaded = overlay_mod.load("pipa-isms-p")

    baselines = json.loads((REPO_ROOT / "catalogs" / "nist-800-53r5" /
                            "baselines.json").read_text(encoding="utf-8"))
    in_any = set().union(*baselines.values())
    catalog_ids = {json.loads(line)["id"]
                   for line in (REPO_ROOT / "catalogs" / "nist-800-53r5" /
                                "AC.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()}
    orphan = sorted(catalog_ids - in_any)[0]

    loaded = copy.deepcopy(loaded)
    target = loaded["mappings"][0]
    target["controls"] = [orphan]
    target["standalone"] = False

    result = overlay_mod.evaluate(loaded, derived["controls"])
    unreachable = {r["clause"] for r in result["unreachable"]}
    assert target["clause"] in unreachable
    assert not (unreachable & {r["clause"] for r in result["uncovered"]})

    rendered = overlay_mod.render(result, "test")
    assert "can never report as reached" in rendered


def test_the_programme_layer_is_selected_at_every_impact_level(profile):
    """SP 800-53B assigns no PM control to Low, Moderate, or High.

    Read as "four baselines and nothing else", thirteen PM controls sat in the
    catalogue unreachable by any derivation, and five compliance clauses that
    map to them were permanently unreportable -- reported as tool advisories,
    which reads as a mapping error rather than a missing layer.
    """
    baselines = json.loads((REPO_ROOT / "catalogs" / "nist-800-53r5" /
                            "baselines.json").read_text(encoding="utf-8"))
    for impact in ("low", "moderate", "high"):
        assert not [c for c in baselines[impact] if c.startswith("PM-")], \
            f"{impact} baseline should carry no PM control"
    assert {"PM-1", "PM-2", "PM-29"} <= set(baselines["program"])

    # Enhancements are tailored, not automatic, and NIST shows this in its own
    # privacy baseline: PM-5(1) and PM-20(1) are selected there, PM-7(1),
    # PM-16(1), and PM-30(1) nowhere. Selecting all five unconditionally would
    # be this tool prescribing where the publication tailors.
    assert not [c for c in baselines["program"] if "(" in c]

    # It has to hold at every level, including the one where nothing else does.
    low = copy.deepcopy(profile)
    low["declared"]["data_types"] = [{"id": "public_content"}]
    for candidate in (profile, low):
        result = sb.run(candidate)
        assert set(baselines["program"]) <= set(result["controls"]), \
            "the programme layer must reach the derived list, not only its own key"


def test_the_programme_layer_lands_on_the_organisation(profile):
    """Thirty-two organisational controls folded into a team's list would bury
    the ones that are the team's. Asserted against what the classifier actually
    produces, not against the layer file it reads."""
    baselines = json.loads((REPO_ROOT / "catalogs" / "nist-800-53r5" /
                            "baselines.json").read_text(encoding="utf-8"))
    derived = sb.run(profile)
    result = classify_resp.classify(profile, derived["controls"])
    program = set(baselines["program"])
    landed = {e["control"]: e["responsibility"] for e in result["controls"]
              if e["control"] in program}
    assert landed, "the programme controls must reach the classifier"
    assert set(landed.values()) == {"org"}, \
        f"programme controls must not become team work: {sorted(set(landed.values()))}"


@pytest.mark.parametrize("overlay_id", ALL_OVERLAYS)
def test_clause_buckets_partition_the_overlay(overlay_id, profile):
    """Every clause lands in exactly one bucket, or the counts do not add up to
    what the reader is told the regime contains."""
    derived = sb.run(profile)
    loaded = overlay_mod.load(overlay_id)
    result = overlay_mod.evaluate(loaded, derived["controls"])
    buckets = ["covered", "partial", "uncovered", "unreachable", "standalone"]
    seen = [r["clause"] for b in buckets for r in result[b]]
    assert len(seen) == len(set(seen))
    assert result["clause_count"] == len(seen) == len(loaded["mappings"])


def test_a_public_repository_declaring_confidential_source_is_questioned(profile):
    """Found on an open-source training tool. The profile already held both
    facts -- repository public, source declared as confidential intellectual
    property -- and said nothing, so it derived a 370-control baseline."""
    p = copy.deepcopy(profile)
    p["repo"]["visibility"] = "PUBLIC"
    p["declared"]["data_types"] = [{"id": "source_code_ip"}]
    assert any("public" in w for w in sb.run(p)["consistency_warnings"])

    resolved = copy.deepcopy(p)
    resolved["declared"]["data_types"] = [{"id": "source_code_ip", "modifiers": ["intended_public"]}]
    assert sb.run(resolved)["consistency_warnings"] == []

    private = copy.deepcopy(p)
    private["repo"]["visibility"] = "private"
    assert sb.run(private)["consistency_warnings"] == []


def test_curation_covers_three_providers():
    """Curation must not be AWS-shaped. Two public GCP repositories came back
    with every managed service unverified."""
    services = REPO_ROOT / "responsibility" / "services"
    providers = set()
    for path in services.glob("*.yaml"):
        providers.add(yaml.safe_load(path.read_text(encoding="utf-8"))["provider"])
    assert {"aws", "azure", "gcp"} <= providers


def test_gke_network_policy_is_the_team_s(profile):
    """Enabling policy enforcement is not the control: a cluster with it on and
    no policies written behaves exactly like one without it."""
    p = copy.deepcopy(profile)
    p["inferred"]["csp"] = "gcp"
    p["inferred"]["deployment_model"] = "kubernetes"
    p["inferred"]["managed_services"] = [{"id": "gcp-gke"}]
    result = classify_resp.classify(p, ["SC-7", "IA-5"])
    assert all(e["responsibility"] == "team" for e in result["controls"])
    assert result["controls"][0]["source"] == "services/gcp-gke.yaml"


@pytest.mark.parametrize("written,expected", [
    ("azurerm", "azure"), ("azuread", "azure"), ("google", "gcp"),
    ("google-beta", "gcp"), ("alicloud", "alibaba"), ("amazon", "aws"),
    ("oracle", "oci"), ("tencentcloud", "tencent"),
])
def test_terraform_provider_names_resolve(profile, written, expected):
    """Found on terragoat, which declares five providers.

    A Terraform block says `provider "azurerm"`, never `provider "azure"`, so
    the vocabulary that matters is the one in the source the profile is inferred
    from rather than the one in the shared responsibility documentation. Every
    name Terraform uses was unrecognised, which meant no inheritance was claimed
    for any cloud but AWS.
    """
    p = copy.deepcopy(profile)
    p["inferred"]["csp"] = written
    result = classify_resp.classify(p, ["PE-4"])
    assert result["csp_status"] == "single"
    assert result["csp"] == expected


def test_one_unknown_provider_does_not_discard_the_known_ones(profile):
    """Discarding the whole list because one member is unfamiliar throws away
    what the profile supplied: a repository declaring aws alongside an unknown
    provider still has a shared responsibility model for the aws half."""
    p = copy.deepcopy(profile)
    p["inferred"]["csp"] = ["aws", "weirdcloud"]
    p["inferred"]["deployment_model"] = "iaas"
    p["inferred"]["managed_services"] = []
    result = classify_resp.classify(p, ["PE-4", "MP-3"])
    assert result["csp_status"] == "partial"
    assert result["csp_declared"] == ["aws"]
    assert any(e["responsibility"] == "csp_claimed" for e in result["controls"])


def test_five_providers_still_report_as_multiple(profile):
    p = copy.deepcopy(profile)
    p["inferred"]["csp"] = ["aws", "azurerm", "google", "alicloud", "oci"]
    result = classify_resp.classify(p, ["SC-7"])
    assert result["csp_status"] == "multiple"
    assert result["csp_declared"] == ["aws", "azure", "gcp", "alibaba", "oci"]


@pytest.mark.parametrize("written", ["UNDETERMINED", "unknown", "TBD", "n/a", "?", "-"])
def test_the_schema_recognises_its_own_sentinels(profile, written):
    """The schema tells an author to write UNDETERMINED where inference failed.
    Treating that as a value produced "region UNDETERMINED is not in the region
    map", which reads as though it were a place."""
    p = copy.deepcopy(profile)
    p["inferred"]["region_storage"] = written
    assert sb.run(p)["cross_border"] is None


def test_no_authentication_is_not_the_same_as_unknown(profile):
    """`auth_mechanism: none` says the service has no authentication, which is a
    finding. Collapsing it into the sentinel would lose that."""
    p = copy.deepcopy(profile)
    p["inferred"]["auth_mechanism"] = "none"
    sb.run(p)
    assert p["inferred"]["auth_mechanism"] == "none"

    q = copy.deepcopy(profile)
    q["inferred"]["auth_mechanism"] = "UNDETERMINED"
    sb.run(q)
    assert q["inferred"]["auth_mechanism"] == "undetermined"


# ---------------------------------------------------------------------------
# shape detection
#
# Two rules were tried and both failed on ordinary input, in opposite
# directions. An allow-list of web protocols called an MQTT broker and a
# Chinese-described API "not a service". A block-list of non-service words
# called a library, a docs generator, and a notebook directory services. The
# resolution is three-valued: say so where neither list fires.
# ---------------------------------------------------------------------------

def _shape(entrypoints, stack=None):
    return sb.run({"inferred": {"entrypoints": entrypoints, "stack": stack or []},
                   "declared": {"data_types": [{"id": "basic_contact"}],
                                "availability": {"rto": "rto_hours", "rpo": "rpo_hours_plus"}}})


@pytest.mark.parametrize("entrypoint", [
    "http: orders api", "mqtt: telemetry topic", "kafka: events topic",
    "modbus tcp: plc registers", "smtp: inbound mail", "sftp: partner drop",
    "grpc: checkout", "udp: agent thrift", "scheduler: DAG dispatch",
])
def test_a_served_system_is_a_service_whatever_it_speaks(entrypoint):
    """The allow-list knew only web protocols, so an event-driven or industrial
    system read as a library and had its ASVS level suppressed."""
    assert _shape([entrypoint])["shape"]["shape"] == "service"


@pytest.mark.parametrize("entrypoints", [
    ["cli: tool"], ["library import", "cli"], ["terraform definitions"],
    ["helm chart"], ["sdk"],
])
def test_things_that_are_not_served_are_still_recognised(entrypoints):
    assert _shape(entrypoints)["shape"]["shape"] == "non_service"


@pytest.mark.parametrize("entrypoint", [
    "public api surface for consumers", "static site output",
    "fixtures and golden files", "notebooks", "action: runs in a workflow",
])
def test_an_ambiguous_entrypoint_is_assumed_not_asserted(entrypoint):
    """Inverting the rule created the opposite failure: a library described as
    an API read as a service. Neither list is complete, so where neither fires
    the derivation assumes a service and says that it assumed."""
    result = _shape([entrypoint])
    assert result["shape"]["shape"] == "service_assumed"
    assert "nothing in the entrypoints says this is served" in sb.render_gate(result)


def test_one_served_entrypoint_outweighs_a_cli():
    """A tool that also listens is a service. The block-list must not win on a
    single non-service word."""
    assert _shape(["cli: ctl", "http: admin ui"])["shape"]["shape"] == "service"


def test_asvs_follows_the_application_surface_not_the_shape():
    """ASVS is a web and API standard. Issuing a level for a Modbus gateway
    asserts an applicable standard that is not, which is the error the PCI
    depth note exists to prevent."""
    assert _shape(["modbus tcp: plc registers"])["asvs_level"] is None
    assert _shape(["http: orders api"])["asvs_level"] == 2
    # A stack signal carries the same meaning where the entrypoints are written
    # in a language the token list does not cover.
    assert _shape(["接口: 订单查询"], ["spring-boot"])["asvs_level"] == 2


# --- self-hosted Kubernetes: two defects found on Airflow and Jaeger ----------
#
# Both repositories run on Kubernetes with no cloud provider, which is how a
# great many services actually run. The tool had two things wrong about them.

def _selfhosted_k8s_profile():
    return {
        "inferred": {"csp": "none", "deployment_model": "kubernetes",
                     "stack": ["python"], "entrypoints": ["http: REST API"]},
        "declared": {"data_types": [{"id": "internal_ops"}], "users": ["internal_staff"]},
    }


def test_kubernetes_does_not_presume_a_cloud_provider():
    """Kubernetes runs on bare metal, on kind, on k3s in a cupboard.

    It sat on the list beside serverless, paas, and saas -- models that
    genuinely cannot exist without a provider -- so every self-hosted cluster
    was told its profile was incoherent and that controls had been reassigned
    as though something had gone wrong. Nothing had.
    """
    profile = _selfhosted_k8s_profile()
    result = classify_resp.classify(profile, ["AC-2", "SC-13", "SI-2"])
    assert result["csp_model_inconsistent"] is False
    assert "presumes a cloud provider" not in classify_resp.render(result)


def test_shared_collapses_to_team_when_there_is_no_provider():
    """A division needs two parties.

    The phantom-claimant rule was written for csp_claimed and stopped there, so
    a self-hosted cluster carried forty-eight controls shared with nobody. Where
    a control was split between a provider and the team and there is no
    provider, the team holds both halves.
    """
    profile = _selfhosted_k8s_profile()
    result = classify_resp.classify(profile, ["AC-2", "SC-13", "SI-2", "AU-2"])
    assert not [e for e in result["controls"]
                if e["responsibility"] in ("shared", "csp_claimed")]


def test_shared_survives_when_a_provider_is_present():
    """The collapse must be conditional on the absence, not unconditional."""
    profile = _selfhosted_k8s_profile()
    profile["inferred"]["csp"] = "aws"
    profile["inferred"]["managed_services"] = [{"id": "aws-eks"}]
    result = classify_resp.classify(profile, ["AC-2", "SC-13", "SI-2", "AU-2"])
    assert [e for e in result["controls"] if e["responsibility"] == "shared"]


# --- one flag, not three lists -----------------------------------------------
#
# "What makes GDPR apply" was written down three times: the classification
# table's personal_data flag (nine types), the same table's per-type
# regulatory_triggers routing (three), and the overlay's own applies_when list
# (eight). Three copies, three answers, and the smallest of them decided
# routing. Found on a profile holding EU users' own content.

def _catalog_types():
    import yaml
    from pathlib import Path
    table = yaml.safe_load((REPO_ROOT / "catalogs" / "data-types" /
                            "classification.yaml").read_text(encoding="utf-8"))
    return table, {e["id"]: e for e in table["types"]}


def test_gdpr_scope_is_not_a_copy_of_the_personal_data_flag():
    """The overlay must read the flag, not restate it.

    Restated, it drifted by one type and the drift failed silently in the
    direction that says a regulation does not apply.
    """
    import yaml
    meta = yaml.safe_load((REPO_ROOT / "overlays" / "gdpr" /
                           "meta.yaml").read_text(encoding="utf-8"))
    condition = meta["applies_when"]
    assert condition.get("data_types_personal") is True
    assert "data_types_any" not in condition


def test_every_personal_type_routes_to_gdpr():
    """The routing follows the flag for all nine types, not the three that named it."""
    table, types = _catalog_types()
    flagged = [k for k, v in types.items() if v.get("personal_data")]
    assert len(flagged) >= 9
    for type_id in flagged:
        profile = {
            "version": "0.1.0",
            "inferred": {"csp": "none", "deployment_model": "onprem",
                         "stack": ["python"], "entrypoints": ["http: REST API"]},
            "declared": {"data_types": [{"id": type_id}], "users": ["public_users"],
                         "user_regions": ["DE"],
                         "availability": {"rto": "rto_hours", "rpo": "rpo_minutes"}},
        }
        result = sb.run(profile)
        assert "gdpr" in {o["id"] for o in result["overlay_triggers"]}, \
            f"{type_id} is flagged personal data but did not route to GDPR"


def test_a_regime_whose_scope_is_not_personal_data_keeps_its_own_list():
    """HIPAA and PCI list types because that *is* their scope.

    Protected health information and account data are not "personal data with a
    narrower list"; collapsing them onto the flag would put GDPR's scope on a US
    health regulation. The fix applies to the regime that drifted, not to all.
    """
    import yaml
    for overlay_id, expected in (("hipaa-security-rule", "health_records"),
                                 ("pci-dss", "payment_card_raw")):
        meta = yaml.safe_load((REPO_ROOT / "overlays" / overlay_id /
                               "meta.yaml").read_text(encoding="utf-8"))
        assert expected in meta["applies_when"]["data_types_any"]
        assert not meta["applies_when"].get("data_types_personal")


def test_gdpr_still_declines_where_nothing_personal_is_declared():
    """Reading the flag must not turn the trigger into "always"."""
    profile = {
        "version": "0.1.0",
        "inferred": {"csp": "none", "deployment_model": "onprem",
                     "stack": ["java"], "entrypoints": ["http: web UI"]},
        "declared": {"data_types": [{"id": "config_secrets"}, {"id": "audit_logs"}],
                     "users": ["internal_staff"], "user_regions": ["FR"],
                     "availability": {"rto": "rto_hours", "rpo": "rpo_minutes"}},
    }
    result = sb.run(profile)
    assert "gdpr" not in {o["id"] for o in result["overlay_triggers"]}


# --- the command line, not the functions behind it ---------------------------
#
# `evaluate()` lost a parameter it no longer needed and `main()` kept passing
# it. Every overlay run from the command line raised TypeError, and the whole
# suite stayed green, because two hundred and fifty tests called `evaluate()`
# directly and not one of them ran the command a person runs. A signature is
# not an interface.

@pytest.fixture(scope="module")
def cli_workspace(tmp_path_factory, profile):
    """A derivation on disk, the way each command actually receives one."""
    work = tmp_path_factory.mktemp("cli")
    profile_path = work / "profile.yaml"
    profile_path.write_text(yaml.safe_dump(profile, allow_unicode=True), encoding="utf-8")
    controls_path = work / "controls.json"

    r = _run_cli("select_baseline.py", str(profile_path), "--json", str(controls_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert controls_path.exists()
    return work, profile_path, controls_path


def _run_cli(script, *args):
    import subprocess
    return subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / script), *args],
                          capture_output=True, text=True)


def test_select_baseline_runs_from_the_command_line(cli_workspace):
    work, profile_path, _ = cli_workspace
    r = _run_cli("select_baseline.py", str(profile_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Impact derivation" in r.stdout


def test_classify_resp_runs_from_the_command_line(cli_workspace):
    work, profile_path, controls_path = cli_workspace
    r = _run_cli("classify_resp.py", str(profile_path), str(controls_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "team implements" in r.stdout


@pytest.mark.parametrize("overlay_id", ALL_OVERLAYS)
def test_every_overlay_runs_from_the_command_line(overlay_id, cli_workspace):
    """--force, so that a decline does not stand in for a working command."""
    work, profile_path, controls_path = cli_workspace
    out = work / f"{overlay_id}.json"
    r = _run_cli("apply_overlay.py", overlay_id, str(profile_path), str(controls_path),
                 "--force", "--json", str(out))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "clauses" in r.stdout
    assert json.loads(out.read_text(encoding="utf-8"))["clause_count"] > 0


def test_merge_runs_from_the_command_line(cli_workspace):
    work, profile_path, controls_path = cli_workspace
    resp = work / "resp.json"
    r = _run_cli("classify_resp.py", str(profile_path), str(controls_path), "--json", str(resp))
    assert r.returncode == 0, r.stdout + r.stderr

    threats = work / "threats.yaml"
    threats.write_text(yaml.safe_dump({"version": "0.1.0", "threats": []}), encoding="utf-8")
    r = _run_cli("merge.py", "--cross", "--controls", str(controls_path),
                 "--responsibility", str(resp), "--threats", str(threats),
                 "--out", str(work / "cross.json"))
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_shared_hint_over_an_all_organisational_mapping_must_be_explained(tmp_path):
    """The guard that stops resolving an advisory and hiding it being one edit.

    `shared` is the honest answer where a regime's obligation has an
    organisational half and a system half -- and it is also the value that
    silences the team-versus-layer advisory. Where the whole mapping still
    resolves away from the team, it has to say which half is the team's.

    The scope is deliberate, and it was questioned in review: adding one
    team-layer or shared-layer control to the mapping does make the check stop
    firing. That is not a loophole, it is the condition being satisfied. The
    note exists to identify the team's half; a mapped control the layer already
    assigns to the team identifies it without prose.
    """
    import shutil
    import validate_overlays as vo

    work = tmp_path / "overlays"
    shutil.copytree(REPO_ROOT / "overlays", work)

    target = work / "gdpr" / "mappings.jsonl"
    rows = [json.loads(l) for l in target.read_text(encoding="utf-8").splitlines() if l.strip()]
    for row in rows:
        if row["clause"] == "Art. 15":
            row.pop("responsibility_note", None)
    target.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                      encoding="utf-8")

    original_overlays, original_root = overlay_mod.OVERLAYS, vo.REPO_ROOT
    try:
        overlay_mod.OVERLAYS = work
        vo.REPO_ROOT = tmp_path
        errors = []
        vo.print = lambda *a, **k: errors.append(" ".join(str(x) for x in a))  # type: ignore[attr-defined]
        code = vo.main([])
    finally:
        overlay_mod.OVERLAYS, vo.REPO_ROOT = original_overlays, original_root
        del vo.print

    assert code == 1
    assert any("Art. 15" in line and "responsibility_note" in line for line in errors), errors


# --- fields that documented a behaviour nothing performed --------------------
#
# Four of these have now been found: forces_requirements, availability_hint,
# the privacy set the derivation computed and dropped, and these two. A sweep
# for data-file keys that appear in no source file is the cheapest way to find
# the next one.

def test_a_refused_modifier_says_it_was_refused(profile):
    """The table records why encryption is not grounds for reduction -- it is
    the outcome of a requirement, so accepting it lets a requirement delete
    itself. Reported as "unknown modifier", a deliberate refusal reads as a
    typo, and the next thing the author tries is `encrypted`, then `at_rest`."""
    bad = copy.deepcopy(profile)
    bad["declared"]["data_types"] = [{"id": "internal_ops", "modifiers": ["encrypted_at_rest"]}]
    with pytest.raises(sb.ProfileError) as exc:
        sb.run(bad)
    assert "refused, not missing" in str(exc.value)
    assert "outcome of a requirement" in str(exc.value)

    # A real typo must still read as one, and say what was on offer.
    bad["declared"]["data_types"] = [{"id": "internal_ops", "modifiers": ["encrpyted"]}]
    with pytest.raises(sb.ProfileError) as exc:
        sb.run(bad)
    assert "unknown modifier" in str(exc.value)
    assert "intended_public" in str(exc.value)


def test_a_service_from_another_provider_is_reported(profile):
    """Each curated file records the provider it describes, and nothing compared
    it against the provider the profile names. A profile saying csp: gcp while
    listing aws-s3 took AWS's split -- forty controls claimed by a provider,
    carrying AWS's evidence references -- into a document about a Google
    deployment, silently."""
    mixed = copy.deepcopy(profile)
    mixed["inferred"]["csp"] = "gcp"
    mixed["inferred"]["managed_services"] = [{"id": "aws-s3"}, {"id": "gcp-gke"}]
    result = classify_resp.classify(mixed, ["AC-3", "SC-13", "MP-6"])

    assert any("aws-s3" in line and "aws" in line for line in result["services_foreign"])
    assert not any("gcp-gke" in line for line in result["services_foreign"])

    rendered = classify_resp.render(result)
    assert "belongs to a provider this profile does" in rendered
    assert "name the wrong company" in rendered


def test_a_multi_cloud_profile_is_not_warned_about(profile):
    """Reported rather than dropped, and not reported when it is not a problem:
    a profile that names both providers is simply multi-cloud."""
    mixed = copy.deepcopy(profile)
    mixed["inferred"]["csp"] = ["aws", "gcp"]
    mixed["inferred"]["managed_services"] = [{"id": "aws-s3"}, {"id": "gcp-gke"}]
    result = classify_resp.classify(mixed, ["AC-3", "SC-13"])
    assert not result["services_foreign"]


# --- a high water mark that could be talked down ------------------------------

def _one_type(type_id, **declared):
    return {"version": "0.1.0",
            "inferred": {"csp": "none", "deployment_model": "onprem",
                         "stack": ["python"], "entrypoints": ["http: REST API"]},
            "declared": {"data_types": [{"id": t} for t in ([type_id] if isinstance(type_id, str) else type_id)],
                         "users": ["internal_staff"],
                         "availability": {"rto": "rto_hours", "rpo": "rpo_minutes"},
                         **declared}}


def test_a_concrete_level_survives_deferral_on_the_other_axis():
    """A type is deferred as soon as *either* axis reads inherit_max.

    The deferred pass then wrote a categorisation snapshot to both axes, which
    is right for the axis that inherits and throws away the table's answer on
    the axis that does not. ml_training_data -- confidentiality inherit_max,
    integrity moderate -- derived LOW integrity on its own, from a table that
    says moderate. A water mark the axis beside it can talk down is not a water
    mark.
    """
    table = yaml.safe_load((REPO_ROOT / "catalogs" / "data-types" /
                            "classification.yaml").read_text(encoding="utf-8"))
    spec = {t["id"]: t for t in table["types"]}["ml_training_data"]
    assert spec["confidentiality"] == "inherit_max" and spec["integrity"] == "moderate"

    assert sb.run(_one_type("ml_training_data"))["impact"]["integrity"]["level"] == "moderate"

    # And adding something lower must not lower it.
    assert sb.run(_one_type(["internal_ops", "ml_training_data"])
                  )["impact"]["integrity"]["level"] == "moderate"

    # The exclusion it was protecting still holds: a type that inherits on both
    # axes must not launder system information into the water mark.
    assert sb.run(_one_type(["config_secrets", "audit_logs"])
                  )["impact"]["confidentiality"]["level"] == "low"


def test_an_integrity_reason_never_exceeds_its_own_answer():
    """"audit and access logs: high" printed under "Integrity LOW".

    Both were correct -- the high came from content the water mark excludes --
    and a reader cannot tell that from a bare number. Confidentiality had
    explained itself since the exclusion was introduced; integrity was left
    bare, which was an oversight rather than a distinction.
    """
    # config_secrets is what creates the excess: it is system information, so it
    # stays out of the water mark while still being content an inheriting store
    # would hold.
    result = sb.run(_one_type(["internal_ops", "app_logs", "config_secrets", "audit_logs"]))
    integrity = result["impact"]["integrity"]
    assert integrity["level"] == "low"
    exceeds = [line for line in integrity["because"]
               if line.rstrip().endswith(": high") or line.rstrip().endswith(": moderate")]
    assert exceeds, "this fixture exists to produce one"
    for line in exceeds:
        assert "the excess coming from system information" in line, \
            f"a reason above the answer must say why: {line}"


def test_a_missing_authentication_is_a_finding_not_a_blank():
    """`auth_mechanism` was gathered, given a rule of its own so that `none`
    would survive normalisation -- the schema says the absence "is a finding
    rather than a gap in the interview" -- and then read by nothing. The
    distinction was carefully preserved and carefully discarded."""
    served = _one_type("internal_ops")
    served["inferred"]["auth_mechanism"] = "none"
    warnings = sb.run(served)["consistency_warnings"]
    assert any("declares no authentication" in w for w in warnings)

    # An empty field is a different fact from a deliberate absence, and the
    # message has to distinguish them or the author cannot tell what to write.
    del served["inferred"]["auth_mechanism"]
    warnings = sb.run(served)["consistency_warnings"]
    assert any("no auth_mechanism was recorded" in w for w in warnings)
    # And the message must not claim a difference the derivation does not make:
    # the field selects no control, and saying otherwise overstates it in a tool
    # whose whole output is requirements.
    assert any("Nothing below changes either way" in w for w in warnings)

    # And a service that records one is left alone.
    served["inferred"]["auth_mechanism"] = "oidc"
    assert not sb.run(served)["consistency_warnings"]


def test_a_published_service_is_not_told_to_declare_what_it_declared():
    """Rekor is a transparency log: unauthenticated reads are the design, and
    the profile already carries intended_public. The first version of the check
    told it to go and declare that, which is how a check teaches people to skim
    past it."""
    published = _one_type("internal_ops")
    published["declared"]["data_types"] = [
        {"id": "public_content", "modifiers": ["intended_public"]},
        {"id": "audit_logs"},
    ]
    published["inferred"]["auth_mechanism"] = "none"
    warnings = sb.run(published)["consistency_warnings"]
    assert any("consistent, for reading" in w for w in warnings)
    assert not any("say so against the data types" in w for w in warnings)
    # It must still say what an unauthenticated write path costs.
    assert any("changes state" in w for w in warnings)


def test_one_published_type_does_not_vouch_for_the_whole_service():
    """The reassuring branch was reached by `any(intended_public)`.

    A profile declaring published documentation alongside health records
    derived HIGH confidentiality and was told its unauthenticated reads were
    consistent. Asked of the table instead, it was wrong the other way: a
    transparency log declares audit_logs, whose table value is inherit_max, and
    inheriting from published content it comes out low.
    """
    def warn(types):
        p = _one_type("internal_ops")
        p["declared"]["data_types"] = types
        p["inferred"]["auth_mechanism"] = "none"
        result = sb.run(p)
        return result["impact"]["confidentiality"]["level"], result["consistency_warnings"]

    public = {"id": "public_content", "modifiers": ["intended_public"]}

    level, warnings = warn([public, {"id": "health_records"}])
    assert level == "high"
    assert any("Not everything here is published" in w for w in warnings)
    assert any("health_records" in w for w in warnings), "name what is not published"
    assert not any("consistent, for reading" in w for w in warnings)

    # The transparency-log shape must still be recognised.
    level, warnings = warn([public, {"id": "audit_logs"}, {"id": "config_secrets"}])
    assert level == "low"
    assert any("consistent, for reading" in w for w in warnings)

    # And low is not public: internal operational data declares nothing public.
    level, warnings = warn([{"id": "internal_ops"}])
    assert level == "low"
    assert not any("intended for publication" in w for w in warnings)


def test_inheritance_does_not_depend_on_declaration_order():
    """Two people entering the same facts in a different order got documents
    that explained them differently.

    `[audit_logs, ml_training_data]` had the audit log inherit low and the
    reverse order had it inherit moderate. The system level came out the same
    both ways, so the answer was never wrong -- but a derivation nobody can
    reproduce is not evidence of anything.
    """
    def derive(order):
        result = sb.run(_one_type(order))
        return (result["impact"]["integrity"]["level"],
                [line for line in result["impact"]["integrity"]["because"] if "audit" in line])

    forward = derive(["audit_logs", "ml_training_data"])
    reverse = derive(["ml_training_data", "audit_logs"])
    assert forward == reverse

    # Order-independent and right: the freeze that made it reproducible also
    # hid the concrete axis of a deferred entry, so the log briefly inherited
    # low from a table that says moderate.
    assert forward[0] == "moderate"
    assert "moderate" in forward[1][0]


def test_deferral_is_a_property_of_the_entry_not_of_one_axis():
    """The `allow_inherit` test lived inside the confidentiality branch, so a
    type declaring `integrity: inherit_max` beside a concrete confidentiality
    was evaluated in the first pass against an unfinished pool. No type in the
    table is shaped that way, so nothing had gone wrong -- the machinery simply
    did not implement the rule it describes."""
    import inspect
    source = inspect.getsource(sb.derive_confidentiality_integrity)
    assert 'if not allow_inherit and "inherit_max" in (c_raw, i_raw):' in source

    table = yaml.safe_load((REPO_ROOT / "catalogs" / "data-types" /
                            "classification.yaml").read_text(encoding="utf-8"))
    integrity_only = [t["id"] for t in table["types"]
                      if t["integrity"] == "inherit_max" and t["confidentiality"] != "inherit_max"]
    assert not integrity_only, (
        f"{integrity_only} inherits on integrity alone; the seeding path raises rather "
        f"than guess at its modified confidentiality, so that path needs writing")


# --- system information is a role, not a property of the type -----------------
#
# The exclusion keeps credentials out of categorisation because they sit in
# nearly every service and counting them puts every application with a login on
# the High baseline. For an identity provider, a secrets manager, or a
# credential vault that reading is exactly backwards.

def _idp_profile(modifiers=None):
    creds = {"id": "account_credentials"}
    if modifiers:
        creds["modifiers"] = modifiers
    return {"version": "0.1.0",
            "inferred": {"csp": "none", "deployment_model": "kubernetes", "stack": ["java"],
                         "entrypoints": ["http: OIDC endpoints"], "auth_mechanism": "oidc"},
            "declared": {"data_types": [creds, {"id": "basic_contact"},
                                        {"id": "audit_logs"}, {"id": "config_secrets"}],
                         "users": ["public_users"],
                         "availability": {"rto": "rto_hours", "rpo": "rpo_hours_plus"}}}


def test_credentials_can_be_what_the_service_is_for():
    """An identity provider derived LOW integrity from a table that says high.

    Availability rescued the baseline for the profile that exposed it, which is
    why it survived: give the same service relaxed recovery objectives and the
    baseline itself comes out MODERATE.
    """
    before = sb.run(_idp_profile())
    assert before["impact"]["integrity"]["level"] == "low"
    assert before["baseline"] == "nist-800-53b-moderate"

    after = sb.run(_idp_profile(["service_content"]))
    assert after["impact"]["integrity"]["level"] == "high"
    assert after["impact"]["confidentiality"]["level"] == "high"
    assert after["baseline"] == "nist-800-53b-high"


def test_the_modifier_does_not_restate_the_table():
    """It says the default reading is wrong for this service; the level to use
    is the one already written against the type. A modifier carrying high/high
    of its own would be a second copy of the table, free to drift from it."""
    table = yaml.safe_load((REPO_ROOT / "catalogs" / "data-types" /
                            "classification.yaml").read_text(encoding="utf-8"))
    modifier = table["modifiers"]["service_content"]
    assert modifier.get("categorises") is True
    assert not modifier.get("effect"), "this modifier carries no level of its own"


def test_the_exclusion_is_visible_on_both_axes():
    """Written to confidentiality alone, an identity provider's "Integrity LOW"
    appeared with no trace of the two high-integrity types dropped to produce
    it. The reader could not see the thing that would make them reach for the
    modifier."""
    result = sb.run(_idp_profile())
    for axis in ("confidentiality", "integrity"):
        assert any("excluded from the water mark" in line
                   for line in result["impact"][axis]["because"]), axis


def test_what_the_exclusion_cost_is_printed_beside_the_number():
    """Neither detector width worked, so the cost went on the reason line.

    A check that fires whenever the exclusion mattered fires on eleven of
    eighteen real profiles, which is noise. A check narrow enough to be read
    misses a secrets manager -- config_secrets alongside owner contact details
    and logs -- which then ships a Moderate baseline in silence. The reader is
    already looking at the reason line, directly under the number it produced.
    """
    def excluded_lines(types):
        profile = _one_type("internal_ops")
        profile["declared"]["data_types"] = types
        result = sb.run(profile)
        return {axis: [line for line in result["impact"][axis]["because"] if "excluded" in line]
                for axis in ("confidentiality", "integrity")}

    secrets_manager = excluded_lines([{"id": "config_secrets"}, {"id": "basic_contact"},
                                      {"id": "audit_logs"}])
    assert secrets_manager["confidentiality"], "the exclusion must be visible at all"
    assert all("came out moderate" in line for line in secrets_manager["confidentiality"])
    assert all("it is high here" in line for line in secrets_manager["confidentiality"])

    # Where the exclusion changed nothing, the line says nothing extra.
    unchanged = excluded_lines([{"id": "health_records"}, {"id": "config_secrets"}])
    assert unchanged["confidentiality"]
    assert not any("came out" in line for line in unchanged["confidentiality"])


def test_the_warning_stays_on_the_case_most_likely_to_be_wrong():
    warned = sb.run(_idp_profile())["consistency_warnings"]
    assert any("service_content modifier" in w for w in warned)

    # Silent once answered.
    assert not any("service_content modifier" in w
                   for w in sb.run(_idp_profile(["service_content"]))["consistency_warnings"])

    # A service that merely has a login is not asked.
    ordinary = _idp_profile()
    ordinary["declared"]["data_types"].append({"id": "transaction_history"})
    assert not any("service_content modifier" in w
                   for w in sb.run(ordinary)["consistency_warnings"])


def test_a_backup_service_is_not_told_its_secrets_are_its_purpose():
    """The rule this replaced fired when nothing but system information survived
    categorisation, counting inheriting stores as non-survivors. A backup
    service holding backups of secrets matched exactly that, and was told to
    declare the secrets as what it exists for. An inheriting store has no level
    of its own but can certainly be the product, and no arrangement of the data
    types tells the two apart."""
    profile = _one_type("internal_ops")
    profile["declared"]["data_types"] = [{"id": "config_secrets"}, {"id": "backups"}]
    assert not any("service_content modifier" in w
                   for w in sb.run(profile)["consistency_warnings"])


@pytest.mark.parametrize("type_id,system_information", [
    ("account_credentials", True), ("config_secrets", True),
    ("transaction_history", False), ("basic_contact", False),
])
@pytest.mark.parametrize("declare_service_content", [False, True])
def test_the_two_consumers_of_the_exclusion_answer_separately(type_id, system_information,
                                                              declare_service_content):
    """Counting `.get("system_information")` in the source proved a shape, not a
    behaviour: a rename, a quote style, or an unrelated diagnostic read would
    have moved the number without moving the tool.

    What has to hold is that the two consumers give the answers they own. The
    water mark asks whether a type decides the categorisation. The
    authentication check asks whether a caller without a name could reach it,
    and those are different questions -- sharing a predicate between them let
    incidental API keys drop out of a finding about an unauthenticated
    endpoint, which is one of the ways secrets actually leak.
    """
    entry = {"id": type_id}
    if declare_service_content:
        entry["modifiers"] = ["service_content"]
    profile = _one_type("internal_ops")
    profile["declared"]["data_types"] = [entry, {"id": "audit_logs"}]
    profile["inferred"]["auth_mechanism"] = "none"
    result = sb.run(profile)

    # 1. categorisation: excluded unless the profile says it is the content
    counted = any(type_id in line and "excluded from the water mark" not in line
                  for line in result["impact"]["confidentiality"]["because"]
                  or [])
    spec_excluded = system_information and not declare_service_content
    excluded_line = any("excluded from the water mark" in line
                        for line in result["impact"]["confidentiality"]["because"])
    assert excluded_line is spec_excluded

    # 2. authentication: named regardless, because reachability is not a
    #    property of what the categorisation counts
    warnings = " ".join(result["consistency_warnings"])
    assert "declares no authentication" in warnings
    assert type_id in warnings, "everything declared is assumed reachable"


# --- round three: five more authoritative repositories ------------------------

def _onprem(**declared):
    base = {"version": "0.1.0",
            "inferred": {"csp": "none", "deployment_model": "onprem", "stack": ["java"],
                         "entrypoints": ["http: REST API"], "auth_mechanism": "oidc"},
            "declared": {"data_types": [{"id": "internal_ops"}], "users": ["internal_staff"],
                         "availability": {"rto": "rto_hours", "rpo": "rpo_minutes"}}}
    base["declared"].update(declared)
    return base


def test_a_country_is_an_answer_to_where_data_is_stored():
    """The region map held cloud provider region codes only.

    An on-premise service has no cloud region to give, and `region_storage: KR`
    -- exactly the vocabulary `user_regions` uses two lines down the same
    profile -- came back "not in the region map" and switched cross-border
    detection off. Every on-premise profile tested hit it.
    """
    profile = _onprem(user_regions=["JP"])
    profile["inferred"]["region_storage"] = "KR"
    cross = sb.run(profile)["cross_border"]
    assert cross and not cross["undetermined"]
    assert cross["storage_country"] == "KR"
    assert cross["offshore_for"] == ["JP"]

    # A cloud region still resolves through the map.
    profile["inferred"]["region_storage"] = "ap-northeast-2"
    assert sb.run(profile)["cross_border"]["storage_country"] == "KR"

    # And something that is neither is still reported as undetermined rather
    # than guessed at.
    profile["inferred"]["region_storage"] = "datacentre-3"
    assert sb.run(profile)["cross_border"]["undetermined"] is True


def test_the_korean_trigger_follows_the_flag_too():
    """gdpr_personal_data was made to follow the classification table's
    personal_data flag; pipa_general, its counterpart, was left behind. It
    reached the three types that happened to name it, so a Korean service
    processing pseudonymous analytics -- personal data by the table's own
    reckoning -- was routed to no Korean regime at all."""
    profile = _onprem(data_types=[{"id": "analytics_pseudonymous"}], user_regions=["KR"])
    assert "pipa-isms-p" in sb.run(profile)["applicable_overlays"]

    # Category-specific triggers stay per-type: sensitive data and children are
    # not "personal data with a narrower list".
    table = yaml.safe_load((REPO_ROOT / "catalogs" / "data-types" /
                            "classification.yaml").read_text(encoding="utf-8"))
    following = {k for k, v in table["regulatory_triggers"].items() if v.get("all_personal_data")}
    assert following == {"gdpr_personal_data", "pipa_general"}


def test_isms_p_scope_reads_the_flag_not_a_fourth_copy_of_it(profile):
    """"What is personal data" was written down four times in this repository.

    Three were found and two removed. The fourth was here, in the ISMS-P scope
    selector, holding seven of the nine types -- so a Korean service processing
    pseudonymous analytics was assessed at ISMS scope and told no personal data
    was declared, on a derivation that had just listed some.
    """
    meta = yaml.safe_load((REPO_ROOT / "overlays" / "pipa-isms-p" /
                           "meta.yaml").read_text(encoding="utf-8"))
    assert meta["scope_selector"].get("data_types_personal") is True
    assert "data_types" not in meta["scope_selector"]

    korean = _onprem(data_types=[{"id": "analytics_pseudonymous"}], user_regions=["KR"])
    derived = sb.run(korean)
    _, reason, scope = overlay_mod.applies(overlay_mod.load("pipa-isms-p"), korean, derived)
    assert scope["scope"] == "ISMS-P", reason


def test_a_declared_certification_reaches_the_overlays_that_apply():
    """Q5 asks what regulation or contractual obligation is already fixed, and
    the answer went nowhere: routing came only from the data types, and an
    elective regime has no data type to route from. That is what elective
    means."""
    profile = _onprem(regulations_declared=["SOC 2 Type II", "ISO/IEC 27001"])
    applicable = sb.run(profile)["applicable_overlays"]
    assert "soc2" in applicable and "iso-27001" in applicable

    # Not named, not listed -- an elective regime is a choice, not a default.
    assert not ({"soc2", "iso-27001"} & set(sb.run(_onprem())["applicable_overlays"]))


def _stored_in(region, users):
    profile = _onprem(user_regions=users)
    profile["inferred"]["region_storage"] = region
    return sb.run(profile)["cross_border"]


def test_a_two_letter_word_is_not_a_country():
    """`len(region) == 2 and region.isalpha()` turned shape into fact.

    "AP" is an Asia Pacific abbreviation and became a country; "EU" and "EEA"
    are not countries at all. Each one turned an undetermined location into a
    positive transfer finding, which is guessing in the direction of telling
    someone to spend money.
    """
    for not_a_country in ("AP", "EU", "EEA", "XX", "ZZ"):
        result = _stored_in(not_a_country, ["JP"])
        assert result["undetermined"] is True, not_a_country

    # A country is read as one, and a spelling the standard codes differently
    # is translated rather than refused.
    assert _stored_in("KR", ["JP"])["storage_country"] == "KR"
    assert _stored_in("UK", ["DE"])["storage_country"] == "GB"

    # Cloud region codes still resolve through the map they were written for.
    assert _stored_in("ap-northeast-2", ["JP"])["storage_country"] == "KR"


def test_storage_inside_the_eea_is_not_a_transfer_within_it():
    """The member list was partial, so storage in Austria, Finland, or Estonia
    was reported as an offshore transfer away from EU users -- the opposite of
    the free movement the Regulation establishes, and a requirement the reader
    would have spent money on."""
    for member in ("AT", "FI", "EE", "PT", "LT", "IS", "NO"):
        assert _stored_in(member, ["EU"]) is None, member

    # Per user region, not against the storage country alone: with storage in
    # Germany and users in France and Japan, only Japan is across a border that
    # matters. The first version reported France as well.
    mixed = _stored_in("DE", ["FR", "JP"])
    assert mixed["offshore_for"] == ["JP"]

    # And leaving the area is still a transfer.
    assert _stored_in("US", ["DE", "GB"])["offshore_for"] == ["DE", "GB"]


@pytest.mark.parametrize("declaration,expected", [
    ("ISO/IEC 27001", {"iso-27001"}),
    ("ISO 27001 certified", {"iso-27001"}),
    ("SOC 2 Type II required by our customers", {"soc2"}),
    ("Trust Services Criteria", {"soc2"}),
    ("ISMS-P", set()),                        # a different regime with its own overlay
    ("not SOC 2", set()),
    ("we are not ISO 27001 certified", set()),
    ("aicpa unrelated thing", set()),         # the organisation is not the standard
])
def test_a_declaration_names_one_regime(declaration, expected):
    """Substring matching read "ISMS-P" as a declaration of ISO 27001, because
    its alias list contained "isms" -- the generic term for an information
    security management system. It read "not SOC 2" as a declaration of SOC 2.
    People write down what they are not doing as often as what they are.
    """
    profile = _onprem(regulations_declared=[declaration])
    assert set(sb.run(profile)["applicable_overlays"]) == expected


def test_the_declaration_matcher_exists_once():
    """It existed twice, in select_baseline and in apply_overlay, and agreed
    only because one was copied from the other. Asserted behaviourally: both
    entry points have to give the same answer on the cases that separated
    them."""
    for declaration, expected in (("ISMS-P", False), ("not SOC 2", False),
                                  ("ISO/IEC 27001", True)):
        profile = _onprem(regulations_declared=[declaration])
        via_derivation = "iso-27001" in sb.run(profile)["applicable_overlays"] or \
                         "soc2" in sb.run(profile)["applicable_overlays"]
        via_overlay = any(
            overlay_mod.applies(overlay_mod.load(oid), profile)[0]
            for oid in ("iso-27001", "soc2"))
        assert via_derivation is expected, declaration
        assert via_overlay is expected, declaration


# --- round four: five more authoritative repositories -------------------------

def test_a_bank_account_is_not_cardholder_data():
    """PCI DSS is scoped to cardholder data -- the primary account number and
    what travels with it. A bank account number is not that, and a business
    taking only transfers is outside the standard entirely. The trigger fired on
    every ERP, invoicing, and payroll shape."""
    accounts = _onprem(data_types=[{"id": "bank_account"}], user_regions=["US"])
    assert sb.run(accounts)["applicable_overlays"] == []

    for in_scope in ("payment_card_raw", "payment_token"):
        cards = _onprem(data_types=[{"id": in_scope}], user_regions=["US"])
        assert "pci-dss" in sb.run(cards)["applicable_overlays"], in_scope


def test_a_bank_account_carries_a_name():
    """The label has said "bank account numbers and holder names" all along.
    Unflagged, a European service holding only bank details was told the
    Regulation did not reach it."""
    table = yaml.safe_load((REPO_ROOT / "catalogs" / "data-types" /
                            "classification.yaml").read_text(encoding="utf-8"))
    assert {t["id"]: t for t in table["types"]}["bank_account"].get("personal_data") is True

    european = _onprem(data_types=[{"id": "bank_account"}], user_regions=["DE"])
    assert "gdpr" in sb.run(european)["applicable_overlays"]


def test_low_is_not_the_answer_when_there_is_no_answer():
    """`highest([])` returns low, so a profile whose every declared type either
    inherits its level or is kept out of the water mark derived LOW with the
    same confidence as one that had been reasoned about.

    A Kubernetes backup tool is exactly that profile, and its whole job is
    holding copies of everything.
    """
    backup_tool = _onprem(data_types=[{"id": "backups"}, {"id": "config_secrets"},
                                      {"id": "audit_logs"}])
    result = sb.run(backup_tool)
    assert result["impact"]["confidentiality"]["from_types"] == 0
    assert result["impact"]["integrity"]["from_types"] == 0
    assert any("absence of an answer" in w for w in result["consistency_warnings"])

    # Say what is being copied and the question is answerable again.
    backup_tool["declared"]["data_types"].append({"id": "health_records"})
    answered = sb.run(backup_tool)
    assert answered["impact"]["confidentiality"]["level"] == "high"
    assert not any("absence of an answer" in w for w in answered["consistency_warnings"])


def test_the_snapshot_an_inheriting_type_writes_is_not_evidence():
    """The deferred pass writes a categorisation snapshot into the pool for the
    axis that inherits. Counting the pool's length therefore made an empty water
    mark look like a reasoned one -- the backup profile reported two
    contributing types when neither had a level of its own."""
    only_inheriting = _onprem(data_types=[{"id": "backups"}, {"id": "audit_logs"}])
    assert sb.run(only_inheriting)["impact"]["confidentiality"]["from_types"] == 0

    mixed = _onprem(data_types=[{"id": "backups"}, {"id": "internal_ops"}])
    assert sb.run(mixed)["impact"]["confidentiality"]["from_types"] == 1


def test_the_overlay_itself_refuses_a_bank_account_only_profile():
    """The first test for this exercised derivation routing from the
    classification table and never called the overlay matcher, so reverting the
    overlay's own applies_when left it passing."""
    accounts = _onprem(data_types=[{"id": "bank_account"}], user_regions=["US"])
    ok, reason, _ = overlay_mod.applies(overlay_mod.load("pci-dss"), accounts)
    assert ok is False
    assert "data type" in reason

    cards = _onprem(data_types=[{"id": "payment_card_raw"}], user_regions=["US"])
    assert overlay_mod.applies(overlay_mod.load("pci-dss"), cards)[0] is True


def test_an_organisations_data_does_not_reach_a_regime_that_protects_people():
    """GDPR protects natural persons and says nothing about legal ones, so a
    purchase ledger of supplier company accounts is not processing personal
    data. Flagging bank_account unconditionally routed exactly that service into
    the Regulation, the privacy baseline, and PIPA."""
    corporate = _onprem(data_types=[{"id": "bank_account", "modifiers": ["legal_entity_only"]}],
                        user_regions=["DE"])
    result = sb.run(corporate)
    assert result["personal_data_types"] == []
    assert result["applicable_overlays"] == []
    assert result["privacy_baseline_applies"] is False

    # The default is still a person's account, because payroll, refunds, and
    # sole traders are the common case.
    personal = _onprem(data_types=[{"id": "bank_account"}], user_regions=["DE"])
    assert "gdpr" in sb.run(personal)["applicable_overlays"]


def test_the_flag_and_the_per_type_trigger_list_agree():
    """Two routes to the same question, and they were free to disagree: a
    profile came out with no personal data and GDPR applying anyway, because the
    type's own regulatory_triggers never consulted the modifier."""
    corporate = _onprem(data_types=[{"id": "basic_contact", "modifiers": ["legal_entity_only"]}],
                        user_regions=["DE"])
    result = sb.run(corporate)
    assert result["personal_data_types"] == []
    assert not result["applicable_overlays"]

    # A regime that is not about personhood is untouched -- a corporate card is
    # still a card.
    cards = _onprem(data_types=[{"id": "payment_card_raw", "modifiers": ["legal_entity_only"]}],
                    user_regions=["US"])
    assert sb.run(cards)["applicable_overlays"] == ["pci-dss"]

    # And the marking is declared on the triggers rather than guessed from names.
    table = yaml.safe_load((REPO_ROOT / "catalogs" / "data-types" /
                            "classification.yaml").read_text(encoding="utf-8"))
    marked = {k for k, v in table["regulatory_triggers"].items()
              if v.get("requires_natural_person")}
    assert "gdpr_personal_data" in marked and "pipa_general" in marked
    assert "pci_dss" not in marked


def test_an_unanswered_axis_is_named_even_when_the_other_is_answered():
    """The check required both axes to be empty. A profile of nothing but model
    training data has genuine integrity evidence and none at all for
    confidentiality, and its confidentiality LOW went on presenting itself as an
    answer."""
    lopsided = _onprem(data_types=[{"id": "ml_training_data"}])
    result = sb.run(lopsided)
    assert result["impact"]["integrity"]["from_types"] == 1
    assert result["impact"]["confidentiality"]["from_types"] == 0
    warned = [w for w in result["consistency_warnings"] if "absence of an answer" in w]
    assert warned and "confidentiality level" in warned[0]
    assert "integrity" not in warned[0].split("is the absence")[0]


# --- round five: five more authoritative repositories -------------------------

def test_one_requirement_per_requirement():
    """Two data types can force the same one. customer_owned on both the files
    and the contact details of a file-sync service put the identical processor
    obligation into the document twice, differing only in a field the reader
    never sees. The team owes one set of obligations, over both sets of data."""
    both = _onprem(data_types=[
        {"id": "user_generated_content", "modifiers": ["customer_owned"]},
        {"id": "basic_contact", "modifiers": ["customer_owned"]},
    ])
    forced = sb.run(both)["forced_requirements"]
    ids = [f["id"] for f in forced]
    assert len(ids) == len(set(ids)), ids

    obligations = next(f for f in forced if f["id"] == "data_processor_obligations")
    assert set(obligations["from_data_types"]) == {"user_generated_content", "basic_contact"}
    assert "user uploads" in obligations["label"] and "member email" in obligations["label"]


def test_one_line_per_overlay_not_per_trigger():
    """Two triggers routing to the same regime printed it twice under different
    names -- "GDPR" and "GDPR Article 9 special category data" -- each pointing
    at the same command."""
    special = _onprem(data_types=[{"id": "sensitive_attributes"}, {"id": "basic_contact"}],
                      user_regions=["DE"])
    result = sb.run(special)
    entries = result["overlay_triggers"]
    assert len(entries) == len({e["id"] for e in entries}), entries

    gdpr = next(e for e in entries if e["id"] == "gdpr")

    assert {t["id"] for t in gdpr["triggers"]} == {"gdpr_personal_data", "gdpr_special_category"}

    rendered = sb.render_gate(result)
    assert rendered.count("scripts/apply_overlay.py gdpr") == 1
    assert "also reached by" in rendered


def test_the_flags_do_not_name_regimes_the_jurisdiction_gate_refused():
    """Emitted raw, regulatory_flags listed the Korean regimes against every
    service holding personal data whatever country its users are in -- and
    nothing reads the field, so nothing was going to correct the impression."""
    european = _onprem(data_types=[{"id": "basic_contact"}], user_regions=["DE"])
    flags = sb.run(european)["regulatory_flags"]
    assert "gdpr_personal_data" in flags
    assert not [f for f in flags if f.startswith("pipa_")]

    korean = _onprem(data_types=[{"id": "basic_contact"}], user_regions=["KR"])
    korean_flags = sb.run(korean)["regulatory_flags"]
    assert "pipa_general" in korean_flags
    assert "gdpr_personal_data" not in korean_flags


def test_a_requirement_forced_twice_from_one_type_keeps_both_reasons():
    """A modifier and the type it sits on can force the same requirement. Both
    arrive with the same data type and different labels and notes, so grouping
    on the data type alone threw the second of each away."""
    table = yaml.safe_load((REPO_ROOT / "catalogs" / "data-types" /
                            "classification.yaml").read_text(encoding="utf-8"))
    modifier_forcing = {m for m, spec in table["modifiers"].items()
                        if spec.get("forces_requirements")}
    assert modifier_forcing, "this test needs a modifier that forces a requirement"

    owned = _onprem(data_types=[{"id": "user_generated_content", "modifiers": ["customer_owned"]}])
    forced = {f["id"]: f for f in sb.run(owned)["forced_requirements"]}

    # The type's own requirement and the modifier's are separate requirements,
    # both present, each naming its own reason.
    assert "upload_validation" in forced and "data_processor_obligations" in forced
    for requirement in forced.values():
        assert requirement["sources"], requirement["id"]
        assert all(s["label"] for s in requirement["sources"])

    # And nothing is stored twice: the summary fields are derived from sources.
    for requirement in forced.values():
        assert requirement["label"] == "; ".join(
            dict.fromkeys(s["label"] for s in requirement["sources"]))
        assert requirement["from_data_types"] == list(
            dict.fromkeys(s["data_type"] for s in requirement["sources"]))


def test_overlay_provenance_has_exactly_one_representation():
    """The first version kept a singular `trigger`/`label` beside the list "for
    compatibility", which made them a second writable copy that answered "which
    regimes reached this overlay" with only part of the truth."""
    special = _onprem(data_types=[{"id": "sensitive_attributes"}, {"id": "basic_contact"}],
                      user_regions=["DE"])
    for entry in sb.run(special)["overlay_triggers"]:
        assert "trigger" not in entry and "label" not in entry
        assert entry["triggers"] and all(t["id"] and t["label"] for t in entry["triggers"])


def test_a_declared_certification_appears_in_the_flags_as_well():
    """A profile declaring SOC 2 had it in applicable_overlays and nowhere in
    regulatory_flags, which claims to hold what is in scope."""
    declared = _onprem(regulations_declared=["SOC 2 Type II"])
    result = sb.run(declared)
    assert "soc2" in result["applicable_overlays"]
    assert "declared:soc2" in result["regulatory_flags"]


def test_a_covered_regulation_is_still_in_scope():
    """`covered` says this repository already addresses the regime, not that the
    regime stopped applying. Skipping before the jurisdiction gate kept it out
    of the flag list the gate is supposed to define. Nothing in the catalogue
    sets it today, so the path is exercised directly."""
    import copy as _copy
    table = yaml.safe_load((REPO_ROOT / "catalogs" / "data-types" /
                            "classification.yaml").read_text(encoding="utf-8"))
    assert not [t for t in table["regulatory_triggers"].values() if t.get("covered")], \
        "if a trigger starts declaring covered, this test should read it instead"

    patched = _copy.deepcopy(table)
    patched["regulatory_triggers"]["gdpr_personal_data"]["covered"] = True
    patched["regulatory_triggers"]["gdpr_personal_data"].pop("overlay", None)

    european = _onprem(data_types=[{"id": "basic_contact"}], user_regions=["DE"])
    original = sb.DATA_TYPES
    try:
        import tempfile, os
        handle = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
        yaml.safe_dump(patched, handle, allow_unicode=True)
        handle.close()
        sb.DATA_TYPES = Path(handle.name)
        result = sb.run(european)
    finally:
        sb.DATA_TYPES = original
        os.unlink(handle.name)

    assert "gdpr_personal_data" in result["regulatory_flags"], \
        "a covered regulation still applies to the service"
    assert not any(u["id"] == "gdpr_personal_data" for u in result["uncovered_regulations"])


# --- round six: twenty more authoritative repositories ------------------------

def test_every_member_state_reaches_the_regulation():
    """Which countries are in the Union was written down three times -- the
    cross-border residency set, the GDPR trigger's region list, and the GDPR
    overlay's -- with thirty, eleven, and twenty members. A service with users
    in Belgium, Austria, Denmark, Finland, Portugal, Greece, Hungary, Romania,
    or Czechia was told the Regulation did not reach it. That is a false
    negative on a regulation for a third of the member states, found on a
    Belgian threat-intelligence platform.
    """
    import profile_schema
    for member in sorted(profile_schema.EEA_MEMBERS):
        profile = _onprem(data_types=[{"id": "basic_contact"}], user_regions=[member])
        assert "gdpr" in sb.run(profile)["applicable_overlays"], member

    # The bloc's own name still works, from either side of the comparison.
    for bloc in ("EU", "EEA"):
        assert "gdpr" in sb.run(_onprem(data_types=[{"id": "basic_contact"}],
                                        user_regions=[bloc]))["applicable_overlays"]

    # And somewhere else is still somewhere else.
    for outside in ("JP", "US", "BR", "AU"):
        assert "gdpr" not in sb.run(_onprem(data_types=[{"id": "basic_contact"}],
                                            user_regions=[outside]))["applicable_overlays"], outside


def test_the_overlay_agrees_with_the_trigger_on_who_is_european():
    """Two of the three lists were consulted by different stages, so a profile
    could be routed to an overlay that then declined it, or the reverse."""
    for member in ("BE", "AT", "LU", "PT", "HR"):
        profile = _onprem(data_types=[{"id": "basic_contact"}], user_regions=[member])
        routed = "gdpr" in sb.run(profile)["applicable_overlays"]
        accepted = overlay_mod.applies(overlay_mod.load("gdpr"), profile)[0]
        assert routed is accepted is True, member


def test_a_modifier_that_cannot_apply_says_so():
    """service_content overrides the system-information exclusion and
    legal_entity_only clears the personal-data reading. Put on a type with
    neither property they did nothing and said nothing, and the author wrote
    them expecting something. Found on a security-telemetry platform."""
    inert = _onprem(data_types=[{"id": "security_telemetry", "modifiers": ["service_content"]}])
    warnings = sb.run(inert)["consistency_warnings"]
    assert any("changed nothing" in w and "service_content" in w for w in warnings)

    working = _onprem(data_types=[{"id": "account_credentials", "modifiers": ["service_content"]}])
    assert not any("changed nothing" in w for w in sb.run(working)["consistency_warnings"])

    # The precondition is declared on the modifier, not hard-coded in the check.
    table = yaml.safe_load((REPO_ROOT / "catalogs" / "data-types" /
                            "classification.yaml").read_text(encoding="utf-8"))
    assert table["modifiers"]["service_content"]["requires"] == "system_information"
    assert table["modifiers"]["legal_entity_only"]["requires"] == "personal_data"


def test_the_interview_answers_reach_the_thing_that_reads_them():
    """Question six offers seven checkboxes; the coverage table is keyed on five
    short names; and not one label matched a key. A profile produced by
    following the documented interview had every answer silently discarded, and
    the tool went on demanding centralised authentication from teams that had
    said they run company-wide SSO -- the one outcome the question exists to
    prevent."""
    import re as _re
    doc = (REPO_ROOT / "skills" / "deriving-security-requirements" / "references" /
           "profile-schema.md").read_text(encoding="utf-8")
    block = doc.split("### Q6")[1].split("```")[1]
    labels = [line.strip("[ ]").strip() for line in block.splitlines() if line.strip().startswith("[")]
    assert len(labels) >= 6, labels

    keys, unknown = classify_resp.normalise_org_controls(labels)
    assert not unknown, f"the interview offers answers the tool cannot read: {unknown}"

    # Every label except the opt-out has to mean something. Asserting only that
    # `keys` is non-empty would pass with six of the seven mapping to nothing.
    opt_out = [l for l in labels if l.lower().startswith("none")]
    assert len(opt_out) == 1, labels
    assert len(keys) == len(labels) - 1, \
        f"{len(labels) - 1} answers should map to a capability, {len(keys)} do: {sorted(keys)}"
    assert keys <= set(classify_resp.ORG_CONTROL_COVERAGE), \
        f"a label maps to a key nothing covers: {keys - set(classify_resp.ORG_CONTROL_COVERAGE)}"

    for label in labels:
        if label in opt_out:
            mapped, _ = classify_resp.normalise_org_controls([label])
            assert mapped == set(), f"{label!r} should select nothing"

    # An answer nobody can read is reported rather than dropped.
    _, unreadable = classify_resp.normalise_org_controls(["quantum firewall"])
    assert unreadable == ["quantum firewall"]


# --- round seven: twenty more, chosen for combinations rather than values -----

def test_gb_and_uk_are_one_country():
    """GB is the ISO 3166-1 code for the United Kingdom and UK is what people
    write. The rules were written with UK and the profiles with GB, so the
    correct code was the one that failed -- it cost the United Kingdom's GDPR
    trigger on every profile that used it. The cross-border check had the alias
    already, which is how one half of the tool came to disagree with the other
    about which countries exist."""
    for spelling in ("GB", "UK", "gb", " uk "):
        profile = _onprem(data_types=[{"id": "basic_contact"}], user_regions=[spelling])
        assert "gdpr" in sb.run(profile)["applicable_overlays"], spelling

    # And the alias does not invent a country out of nowhere.
    for elsewhere in ("JP", "US", "BR"):
        profile = _onprem(data_types=[{"id": "basic_contact"}], user_regions=[elsewhere])
        assert "gdpr" not in sb.run(profile)["applicable_overlays"], elsewhere


def test_silence_about_a_jurisdiction_is_not_a_finding_about_it():
    """A microfinance platform holding national identifiers and biometrics for
    Indian, Kenyan, and Philippine users was shown GDPR and nothing else, with
    no sign that three of its four jurisdictions had simply not been looked at.
    The overlay list is this repository's coverage; printed alone it reads as
    the answer."""
    unmodelled = _onprem(data_types=[{"id": "government_id"}, {"id": "biometric"}],
                         user_regions=["IN", "KE", "PH", "DE"])
    warnings = sb.run(unmodelled)["consistency_warnings"]
    named = [w for w in warnings if "models no data protection regime" in w]
    assert named, warnings
    assert all(code in named[0] for code in ("IN", "KE", "PH"))
    assert "DE" not in named[0], "a jurisdiction that is modelled must not be listed"

    # Coverage means a general data-protection regime, not any trigger that
    # happens to name the country. The first version counted the United States
    # as modelled because HIPAA and COPPA mention it, so a service holding
    # ordinary contact details for American users got no overlay and no word
    # about why -- and this test blessed that by listing US as covered.
    modelled = _onprem(data_types=[{"id": "basic_contact"}], user_regions=["DE", "KR"])
    assert not [w for w in sb.run(modelled)["consistency_warnings"]
                if "models no data protection regime" in w]

    american = _onprem(data_types=[{"id": "basic_contact"}], user_regions=["US"])
    assert [w for w in sb.run(american)["consistency_warnings"]
            if "models no data protection regime" in w], \
        "HIPAA and COPPA naming the US is not general privacy coverage of it"

    # Both spellings of Greece are the same country on both sides of the check.
    for greece in ("GR", "EL"):
        greek = _onprem(data_types=[{"id": "basic_contact"}], user_regions=[greece])
        assert "gdpr" in sb.run(greek)["applicable_overlays"], greece
        assert not [w for w in sb.run(greek)["consistency_warnings"]
                    if "models no data protection regime" in w], greece

    # And a two-letter word that is not a country is not reported as a
    # jurisdiction -- the shape test this file already refused once.
    not_a_country = _onprem(data_types=[{"id": "basic_contact"}], user_regions=["AP"])
    assert not [w for w in sb.run(not_a_country)["consistency_warnings"]
                if "models no data protection regime" in w]

    # And with no personal data there is nothing for a regime to reach.
    impersonal = _onprem(data_types=[{"id": "internal_ops"}], user_regions=["IN"])
    assert not [w for w in sb.run(impersonal)["consistency_warnings"]
                if "models no data protection regime" in w]


def test_an_amplifier_that_can_do_nothing_says_so():
    """internal_tool_only lowers availability and cannot while another amplifier
    raises it. A flight-control profile declared it beside safety_critical and
    the reason list carried both statements without a word.

    The first version of the message claimed the other amplifiers say there is
    no workable manual fallback. They do not: revenue, an SLA, and a downstream
    dependency say nothing about fallbacks, and an internal tool can have one
    and still stop revenue when it breaks. Asserting otherwise turned a fact
    about the tool's arithmetic into a claim about the service.
    """
    together = _onprem()
    together["declared"]["availability"]["amplifiers"] = ["safety_critical", "internal_tool_only"]
    warnings = sb.run(together)["consistency_warnings"]
    assert any("internal_tool_only contributed nothing" in w for w in warnings)
    assert not any("the others say" in w for w in warnings)

    # It fires on any raising amplifier, not only the dramatic one.
    revenue = _onprem()
    revenue["declared"]["availability"]["amplifiers"] = ["revenue_direct", "internal_tool_only"]
    assert any("contributed nothing" in w for w in sb.run(revenue)["consistency_warnings"])

    alone = _onprem()
    alone["declared"]["availability"]["amplifiers"] = ["internal_tool_only"]
    assert not any("contributed nothing" in w for w in sb.run(alone)["consistency_warnings"])

    # And the diagnostic does not leak into the published shape.
    assert "conflicts" not in sb.run(alone)["impact"]["availability"]

    # The precondition is declared on the amplifier, not hard-coded.
    table = yaml.safe_load((REPO_ROOT / "catalogs" / "data-types" /
                            "availability.yaml").read_text(encoding="utf-8"))
    solo = [a["id"] for a in table["amplifiers"] if a.get("only_when_alone")]
    assert solo == ["internal_tool_only"]


# --- round eight: the threat path, which sixty-nine repositories had skipped --

def _threat(threat_id="T1", **kw):
    base = {"id": threat_id, "category": "tampering", "boundary": "client -> api",
            "persona": "an authenticated caller", "scenario": "something happens",
            "novelty": "generic", "related_controls": [], "affected_assets": []}
    base.update(kw)
    return base


def _crossed(profile, threats):
    derived = sb.run(profile)
    resp = classify_resp.classify(profile, derived["controls"])
    return merge.cross(derived, resp, {"version": "0.1.0", "threats": threats})


def test_a_control_the_baseline_does_not_select_is_not_dropped():
    """Sixty-nine public repositories were run with an empty threat model, so
    this stage had only ever seen four synthetic profiles.

    A control the author cited, that exists, and that this baseline does not
    select was being filtered out without a word -- so a supply-chain threat
    citing SR-3, SR-11, and CM-14 reported as fully addressed by two, and
    CM-14, the signed-components control that answers it, was never mentioned.
    """
    profile = _onprem(data_types=[{"id": "internal_ops"}])
    crossed = _crossed(profile, [_threat(related_controls=["SR-3", "SR-11", "CM-14"])])

    outside = crossed["outside_baseline"]
    assert outside and outside[0]["controls"] == ["CM-14"]
    assert outside[0]["partly_covered"] is True

    rendered = merge.render_cross(crossed)
    assert "CM-14" in rendered and "does not select" in rendered

    # A threat whose controls are all outside is a different statement again.
    only_outside = _crossed(profile, [_threat(related_controls=["CM-14"])])
    assert only_outside["outside_baseline"][0]["partly_covered"] is False


def test_novelty_is_a_vocabulary_not_a_sentence():
    """It decides whether a threat raises its controls to high priority, and it
    was compared against one literal with nothing checking the field. A threat
    carrying a sentence where an enum belongs was read as generic, and the
    author had written the most specific thing in the document."""
    profile = _onprem(data_types=[{"id": "internal_ops"}])

    prose = _crossed(profile, [_threat(novelty="no control expresses this at all",
                                       related_controls=["AC-3"])])
    assert any("is not one of" in p for p in [x["message"] for x in prose["problems"]])

    absent = _crossed(profile, [{k: v for k, v in _threat(related_controls=["AC-3"]).items()
                                 if k != "novelty"}])
    assert any("no novelty" in p for p in [x["message"] for x in absent["problems"]])

    # The value that means something still does.
    specific = _crossed(profile, [_threat(novelty="service_specific", related_controls=["AC-3"])])
    assert not [p for p in [x["message"] for x in specific["problems"]] if "novelty" in p]
    raised = next(i for i in specific["items"] if i["control"] == "AC-3")
    assert raised["priority"] == "high"


def test_the_threat_model_and_the_profile_are_held_against_each_other():
    """They are two descriptions of one system and nothing compared them. This
    repository's own golden threat model names account_credentials as an
    affected asset, and its golden profile does not declare that data type --
    which also costs the derivation the credential_storage requirement that
    declaring it would force."""
    profile = _onprem(data_types=[{"id": "internal_ops"}])
    crossed = _crossed(profile, [_threat(affected_assets=["account_credentials"])])
    named = [p for p in crossed["problems"] if p["kind"] == "asset"]
    assert named and "account_credentials" in named[0]["message"]

    agreed = _crossed(profile, [_threat(affected_assets=["internal_ops"])])
    assert not [p for p in agreed["problems"] if p["kind"] == "asset"]

    # A threat crossing a boundary names things that are not data types at all,
    # and the schema never said it should not. Rejecting those made an ordinary
    # threat model look broken.
    neighbours = _crossed(profile, [_threat(
        affected_assets=["upstream identity provider", "the CI runner", "a signing key"])])
    assert not [p for p in neighbours["problems"] if p["kind"] == "asset"]

    # And a problem in the threat model must never be reported as a reference
    # that matched no control: the golden profile's T-08 matched AC-7 and was
    # announced as threat-only in the same breath.
    rendered = merge.render_cross(crossed)
    assert "do not change which" in rendered
    assert "counted as threat-only" not in rendered


# --- round nine: the back half of the pipeline, never run on real input -------

def test_an_identifier_under_the_wrong_key_is_not_silently_unchecked():
    """The worst thing found in this repository.

    The linter exists so that a fabricated `SC-28(4)` -- which reads exactly
    like the three enhancements that are real -- is caught before an auditor
    finds it. It reads `managed.sources`. A document carrying the same
    identifiers under `managed.controls` passed with zero errors: the
    source-integrity check verified nothing and reported success.

    A key the schema does not define is not a stylistic matter. It is the
    difference between a document that was checked and one that was not.
    """
    doc = _doc()
    doc["requirements"][0]["managed"].pop("sources")
    doc["requirements"][0]["managed"]["controls"] = ["SC-28(4)", "ZZ-99"]

    rules = _rules(lint_mod.lint(doc, "en", None))
    assert "unknown-field" in rules
    errors = [f for f in lint_mod.lint(doc, "en", None) if f.level == "ERROR"]
    assert errors, "a document the linter cannot check must not pass"
    assert any("controls" in str(f) for f in errors)

    # Under the right key the same identifiers are caught for what they are.
    doc["requirements"][0]["managed"].pop("controls")
    doc["requirements"][0]["managed"]["sources"] = ["SC-28(4)", "ZZ-99"]
    assert "source-unknown" in _rules(lint_mod.lint(doc, "en", None))


def test_a_requirement_without_a_csf_function_cannot_be_filed():
    """The published document is organised by CSF function, and a requirement
    without one lands in UNCLASSIFIED at the foot of it. Five of five did, and
    nothing said so -- the document's whole organising principle had collapsed
    and it rendered without complaint."""
    doc = _doc()
    doc["requirements"][0]["managed"].pop("csf")
    assert "no-csf" in _rules(lint_mod.lint(doc, "en", None))

    doc = _doc()
    doc["requirements"][0]["managed"].pop("responsibility")
    assert "no-responsibility" in _rules(lint_mod.lint(doc, "en", None))


def test_a_requirement_with_no_sources_is_the_point_not_an_error():
    """Three of the eight golden requirements carry none. A requirement with no
    control identifiers is the threat-only case -- a risk no baseline control
    addresses -- which is this tool's central claim. Requiring `sources` would
    have forbidden the most important kind of requirement it produces."""
    doc = _doc()
    doc["requirements"][0]["managed"].pop("sources")
    assert "no-sources" not in _rules(lint_mod.lint(doc, "en", None))


def test_an_absent_managed_block_is_not_an_empty_statement():
    """A document written in the flat shape got one identical "managed.statement
    is empty" per requirement and no hint that the whole managed/human split had
    been missed."""
    flat = {"requirements": [{"id": "REQ-DATA-ENC-REST-01",
                              "statement": "Data must be encrypted.",
                              "controls": ["SC-28"], "verification": "check it"}]}
    findings = lint_mod.lint(flat, "en", None)
    assert "no-managed-block" in _rules(findings)
    named = [f for f in findings if f.rule == "no-managed-block"][0]
    assert "controls" in str(named) and "statement" in str(named)


def test_a_refresh_that_matches_nothing_is_refused_before_it_writes():
    """The refresh path had never been run on real input either.

    Given a draft whose slugs did not line up with the existing identifiers, it
    retired all five requirements -- including one a human had marked
    accepted_risk, carrying a note the tool is never supposed to touch -- and
    issued five new ones. The CLI writes the file and prints the counts
    afterwards, so by the time anyone could see it the note was gone.

    Total churn is never a real change to a service. It is a changed slug
    convention or an id scheme, every time.
    """
    existing = [
        {"id": "REQ-PKI-SIGNING-KEY-01",
         "managed": {"statement": "The signing key must be non-exportable.",
                     "csf": ["PR.DS-01"], "sources": ["SC-12"], "responsibility": "team"},
         "human": {}},
        {"id": "REQ-PKI-CERT-LIFETIME-01",
         "managed": {"statement": "Workload certificates must expire within 24 hours.",
                     "csf": ["PR.AA-05"], "sources": ["SC-12"], "responsibility": "team"},
         "human": {"status": "accepted_risk", "note": "not achievable this quarter"}},
    ]

    # Slugs that are whole identifiers rather than slugs: nothing matches.
    mismatched = [{"slug": r["id"], "managed": r["managed"]} for r in existing]
    churned = merge.apply_merge(mismatched, existing, {"issued": {}})
    assert churned["total_churn"] is True
    assert len(churned["retired"]) == len(existing)

    # The human's note is still in the record the tool would have written, which
    # is what makes the refusal worth having rather than a nicety.
    retired_record = next(r for r in churned["requirements"]
                          if r["id"] == "REQ-PKI-CERT-LIFETIME-01")
    assert retired_record["human"]["note"] == "not achievable this quarter"
    assert retired_record["human"].get("previous_status") == "accepted_risk"

    # Slugs that line up match, and nothing is churned.
    aligned = [{"slug": r["id"].replace("REQ-", "", 1).rsplit("-", 1)[0],
                "managed": r["managed"]} for r in existing]
    steady = merge.apply_merge(aligned, existing, {"issued": {}})
    assert steady["total_churn"] is False
    assert len(steady["unchanged"]) == len(existing)
    assert not steady["retired"]

    # An empty starting document is not churn -- it is a first run.
    first = merge.apply_merge(aligned, [], {"issued": {}})
    assert first["total_churn"] is False


def test_the_refusal_happens_at_the_command_line_and_before_the_write(tmp_path):
    """The first version of this test called apply_merge and checked the flag,
    so reverting the guard in main() left it green -- and the guard is the whole
    point, because the CLI writes the file and prints the counts afterwards."""
    existing = {"requirements": [
        {"id": "REQ-PKI-SIGNING-KEY-01",
         "managed": {"statement": "The signing key must be non-exportable.",
                     "csf": ["PR.DS-01"], "sources": ["SC-12"], "responsibility": "team"},
         "human": {"status": "accepted_risk", "note": "keep me"}}]}
    existing_path = tmp_path / "requirements.yaml"
    existing_path.write_text(yaml.safe_dump(existing), encoding="utf-8")
    state_path = tmp_path / "state.yaml"
    state_path.write_text("issued: {}\n", encoding="utf-8")
    draft_path = tmp_path / "draft.json"
    draft_path.write_text(json.dumps({"requirements": [
        {"slug": "REQ-PKI-SIGNING-KEY-01",       # an identifier, not a slug
         "managed": existing["requirements"][0]["managed"]}]}), encoding="utf-8")

    before_doc = existing_path.read_bytes()
    before_state = state_path.read_bytes()

    r = _run_cli("merge.py", "--apply", "--draft", str(draft_path),
                 "--existing", str(existing_path), "--state", str(state_path))
    assert r.returncode == 2, r.stdout + r.stderr
    assert "matched nothing" in r.stderr
    assert existing_path.read_bytes() == before_doc, "the file must not be touched"
    assert state_path.read_bytes() == before_state

    # And a rewrite that was meant has a way through, which it must: one
    # requirement genuinely replaced by another looks exactly like this.
    r = _run_cli("merge.py", "--apply", "--allow-full-rewrite", "--draft", str(draft_path),
                 "--existing", str(existing_path), "--state", str(state_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert existing_path.read_bytes() != before_doc


def test_the_allowlist_covers_what_the_rest_of_the_tool_reads():
    """`unverified` is produced by the responsibility split and printed by the
    renderer. Left out of the allowlist, it would have made any document that
    preserved it fail lint -- an allowlist has to cover what the tool reads, not
    what one fixture happens to carry."""
    import re as _re
    read_from_managed = set()
    for script in ("render.py", "merge.py", "lint.py"):
        source = (REPO_ROOT / "scripts" / script).read_text(encoding="utf-8")
        read_from_managed |= set(_re.findall(r'managed(?:\.get\(|\[)"([a-z_]+)"', source))
    assert read_from_managed, "this test needs to find the reads it is checking"
    assert read_from_managed <= lint_mod.MANAGED_KEYS, \
        f"read but not allowed: {sorted(read_from_managed - lint_mod.MANAGED_KEYS)}"


# --- round nine, part two: the documents themselves ---------------------------
#
# A coverage measurement put render.py at 20 per cent -- every one of the three
# document renderers untested, on the script that produces the deliverable.

def _req(req_id, **managed):
    human = managed.pop("human", {})
    base = {"statement": "Data at rest must be encrypted with a customer-managed key.",
            "csf": ["PR.DS-01"], "sources": ["SC-28"], "responsibility": "team"}
    base.update(managed)
    return {"id": req_id, "managed": base, "human": human}


def _documents(requirements):
    doc = {"requirements": requirements}
    titles, meta = render_mod.catalog_titles(), render_mod.catalog_meta()
    return (render_mod.render_requirements(doc, titles, meta),
            render_mod.render_traceability(doc, titles, meta),
            render_mod.render_responsibility(doc, meta))


def test_a_retired_requirement_leaves_a_record_without_publishing_the_reason():
    """Two halves of one problem.

    A retired requirement vanished from every published document, so a reader
    diffing last quarter's deliverable against this one found an absence and no
    account of it. But the account itself belongs to the internal record: a
    retirement reason can name the person who approved an exception, and this
    file is publishable. The ledger says what was retired; it does not reproduce
    why.
    """
    reqs, trace, _ = _documents([
        _req("REQ-A-B-01"),
        _req("REQ-C-D-01", human={"status": "retired",
                                  "retired_reason": "exception approved by the CISO closes"}),
        _req("REQ-E-F-01", human={"status": "superseded"}),
    ])
    assert "1 active requirements." in reqs
    assert "No longer required" in reqs
    assert "REQ-C-D-01" in reqs and "REQ-E-F-01" in reqs
    assert "CISO" not in reqs, "the human record does not cross into the publishable document"
    assert "recorded internally" in reqs
    assert "not recorded" in reqs, "a retirement with no reason is distinguishable"

    for retired in ("REQ-C-D-01", "REQ-E-F-01"):
        assert retired not in trace, "a retired requirement is not an answer to a control"


def test_one_notion_of_retired_across_the_document():
    """`active()` normalises case and whitespace and the ledger compared raw, so
    a status of " RETIRED " fell out of the active sections and out of the
    ledger as well -- excluded twice and mentioned nowhere."""
    reqs, _, _ = _documents([
        _req("REQ-A-B-01"),
        _req("REQ-C-D-01", human={"status": " RETIRED "}),
    ])
    assert "1 active requirements." in reqs
    assert "REQ-C-D-01" in reqs.split("## No longer required")[1]


def test_a_shared_responsibility_publishes_both_halves():
    """The document exists to say who owns what and it said only "shared". The
    linter requires both halves to be described; not printing them left the
    requirement asserting a division it did not publish."""
    _, _, resp = _documents([
        _req("REQ-C-D-01", responsibility="shared", evidence="provider attestation",
             csp_part="Operates the key management service.",
             team_part="Selects the key and enables encryption."),
    ])
    assert "Operates the key management service." in resp
    assert "Selects the key and enables encryption." in resp


def test_a_blank_half_is_not_a_described_one():
    """`csp_part: " "` and `evidence: [""]` are truthy and render as empty
    cells, which defeats the guarantee these rules exist to make."""
    blank = _doc(responsibility="shared", evidence=[""], csp_part=" ", team_part="\t")
    rules = _rules(lint_mod.lint(blank, "en", None))
    assert {"no-evidence", "no-csp-part", "no-team-part"} <= rules


def test_every_document_carries_its_provenance():
    """Three documents, three audiences, and each is published on its own."""
    for document in _documents([_req("REQ-A-B-01")]):
        assert "NIST SP 800-53 Rev 5" in document
        assert "does not constitute" in document, "the disclaimer travels with each file"
        assert "NIST does not endorse this output" in document


def test_traceability_answers_the_question_it_says_it_answers():
    """Control to requirement, including the case where two requirements address
    one control and the case where one requirement cites several."""
    _, trace, _ = _documents([
        _req("REQ-A-B-01", sources=["SC-28", "SC-28(1)"]),
        _req("REQ-C-D-01", sources=["SC-28"]),
    ])
    row = next(line for line in trace.splitlines() if line.startswith("| SC-28 |"))
    assert "REQ-A-B-01" in row and "REQ-C-D-01" in row
    assert "Protection of Information at Rest" in row, "the control's title, not just its id"
    assert any(line.startswith("| SC-28(1) |") for line in trace.splitlines())


def test_the_responsibility_document_keeps_the_promise_it_opens_with():
    """It opens "Inheritance is a claim, not a fact. Every provider-claimed
    control lists the evidence an auditor will ask for" -- and a shared
    requirement with no evidence rendered an empty cell underneath it."""
    _, _, resp = _documents([
        _req("REQ-A-B-01", responsibility="csp_claimed", evidence="SOC 2 Type II report"),
        _req("REQ-C-D-01", responsibility="shared", evidence="provider attestation",
             csp_part="operates the KMS", team_part="supplies the key"),
        _req("REQ-E-F-01", responsibility="team"),
    ])
    for claimed in ("REQ-A-B-01", "REQ-C-D-01"):
        row = next(line for line in resp.splitlines() if claimed in line)
        assert row.rstrip().rstrip("|").split("|")[-1].strip(), f"{claimed} has an empty evidence cell"

    # The linter is what stops an empty one reaching here.
    naked = _doc(responsibility="shared")
    naked["requirements"][0]["managed"].pop("evidence", None)
    rules = _rules(lint_mod.lint(naked, "en", None))
    assert {"no-evidence", "no-csp-part", "no-team-part"} <= rules


def test_an_unverified_inheritance_is_marked_where_it_is_claimed():
    """A service whose curation nobody reviewed is a weaker claim than one that
    was, and the reader is entitled to see which."""
    _, _, resp = _documents([
        _req("REQ-A-B-01", responsibility="csp_claimed", evidence="SOC 2", unverified=True),
    ])
    assert "unverified" in resp


# --- the golden evaluator, at 32% ---------------------------------------------

def test_an_expectation_file_that_cannot_fail_is_reported():
    """Recall is computed over the topics marked must_cover, so a file with none
    scores 1.0 whatever the document says. This module's own docstring says
    widening hints until a failing run passes is how a suite stops measuring
    anything; requiring nothing is the same end by a shorter road."""
    problems = eval_mod.check_expectation(
        {"topics": [{"id": "t", "description": "d", "match_any": ["x"]}]})
    assert any("cannot fail" in p for p in problems)

    ok = eval_mod.check_expectation(
        {"topics": [{"id": "t", "description": "d", "match_any": ["x"], "must_cover": True}]})
    assert not ok


def test_the_fields_read_only_on_the_failing_path_are_checked_up_front():
    """A topic with no `description` scored fine and raised KeyError the moment
    it was reported as missed; a must_not_cover rule with no `why` did the same
    when it fired. The suite worked while it passed and broke while it failed."""
    problems = eval_mod.check_expectation({"topics": [
        {"id": "t", "match_any": ["x"], "must_cover": True}]})
    assert any("no description" in p for p in problems)

    problems = eval_mod.check_expectation({
        "topics": [{"id": "t", "description": "d", "match_any": ["x"], "must_cover": True}],
        "must_not_cover": [{"id": "r", "match_any": ["y"]}]})
    assert any("no `why`" in p for p in problems)


def test_a_hint_list_that_can_never_match_is_reported():
    """An empty match_any leaves the topic permanently missed, which reads as a
    gap in the derivation rather than a gap in the expectation."""
    problems = eval_mod.check_expectation({"topics": [
        {"id": "t", "description": "d", "match_any": [], "must_cover": True}]})
    assert any("never be covered" in p for p in problems)

    scalar = eval_mod.check_expectation({"topics": [
        {"id": "t", "description": "d", "match_any": "tenant", "must_cover": True}]})
    assert any("character by character" in p for p in scalar)


@pytest.mark.parametrize("case", sorted(p.name for p in GOLDEN_ROOT.iterdir() if p.is_dir()))
def test_every_golden_expectation_is_scoreable(case):
    """The four shipped files are complete. Nothing checked that, so the fifth
    would not have been."""
    expected = yaml.safe_load((GOLDEN_ROOT / case / "expected-coverage.yaml").read_text(encoding="utf-8"))
    assert not eval_mod.check_expectation(expected)


def test_the_golden_draft_scores_against_its_own_expectation():
    """The evaluator had never been run. It scores the shipped draft at full
    recall with no excluded subject appearing, which is the property a
    regression in the model stage would break."""
    expected = yaml.safe_load((GOLDEN / "expected-coverage.yaml").read_text(encoding="utf-8"))
    draft = json.loads((GOLDEN / "draft.json").read_text(encoding="utf-8"))["requirements"]
    doc = {"requirements": [
        {"id": merge.issue_id(item["slug"], {"issued": {}}), "managed": item["managed"], "human": {}}
        for item in draft]}
    result = eval_mod.score(expected, doc)
    assert result["recall"] == 1.0
    assert not result["violations"]
    assert not result["critical_missing"]

    # A retired requirement is not evidence of coverage.
    doc["requirements"][0]["human"] = {"status": "retired"}
    assert eval_mod.score(expected, doc)["total_requirements"] == len(draft) - 1


# --- getting the language wrong was silent ------------------------------------

def test_a_statement_in_another_script_says_the_locale_is_wrong():
    """The vague-term check decides whether a requirement can be verified at
    all, and it is the check a wrong locale switches off. A Korean document
    linted as English passed clean while containing '적절히'."""
    korean = _doc(statement="데이터는 적절히 보호되어야 한다.")
    as_english = _rules(lint_mod.lint(korean, "en", None))
    assert "locale-mismatch" in as_english

    as_korean = lint_mod.lint(korean, "ko", None)
    assert "locale-mismatch" not in _rules(as_korean)
    assert "vague" in _rules(as_korean), "and the ko rules find what en could not"

    # Latin script is not claimed for any locale.
    english = _doc(statement="Data at rest must be encrypted with a customer-managed key.")
    assert "locale-mismatch" not in _rules(lint_mod.lint(english, "en", None))
    assert lint_mod.script_of("Data at rest must be encrypted.") is None


def test_an_unsupported_locale_is_refused_rather_than_quietly_english():
    """`VAGUE.get(locale, [])` returns nothing and `MODAL.get` falls back, so a
    Japanese document run with --locale ja got the English rules and no word
    about it."""
    r = _run_cli("lint.py", str(REPO_ROOT / "tests" / "does-not-matter.yaml"), "--locale", "ja")
    assert r.returncode == 2
    assert "not supported" in r.stderr
    assert "en, ko" in r.stderr

    assert lint_mod.script_of("データは保護されなければならない") == "ja"
    assert lint_mod.script_of("数据必须加密") == "zh"


def test_a_threat_list_that_is_a_string_says_so():
    """A string is iterable. Read as a list it produced "threats[0] is 'n'; each
    threat must be a mapping" -- an error naming a character, which is the shape
    of mistake this repository has corrected in four other places."""
    controls = {"controls": ["AC-3"], "forced_requirements": []}
    resp = {"controls": [{"control": "AC-3", "responsibility": "team", "services": []}]}

    with pytest.raises(ValueError) as exc:
        merge.cross(controls, resp, {"threats": "not a list"})
    assert "must be a list" in str(exc.value)
    assert "'n'" not in str(exc.value)

    with pytest.raises(ValueError) as exc:
        merge.cross(controls, resp, {"threats": {"id": "T1"}})
    assert "still goes in a list" in str(exc.value)


def test_a_missing_input_gets_a_sentence(tmp_path):
    """Every other input error in this repository names the file and the flag.
    Pointing --controls at the wrong path produced a stack trace ending in
    FileNotFoundError."""
    r = _run_cli("merge.py", "--cross", "--controls", str(tmp_path / "nope.json"),
                 "--responsibility", str(tmp_path / "r.json"),
                 "--threats", str(tmp_path / "t.yaml"), "--out", str(tmp_path / "o.json"))
    assert r.returncode == 2
    assert "Traceback" not in r.stderr
    assert "does not exist" in r.stderr and "select_baseline.py --json" in r.stderr


def test_no_threat_model_is_not_a_threat_model_that_found_nothing(tmp_path, profile):
    """The difference that hid the largest gap in this repository: sixty-nine
    public repositories were crossed against a threats file that did not exist,
    and the output was indistinguishable from a model that found nothing."""
    derived = sb.run(profile)
    controls = tmp_path / "controls.json"
    controls.write_text(json.dumps(derived), encoding="utf-8")
    resp = tmp_path / "resp.json"
    resp.write_text(json.dumps(classify_resp.classify(profile, derived["controls"])),
                    encoding="utf-8")
    out = tmp_path / "cross.json"

    absent = _run_cli("merge.py", "--cross", "--controls", str(controls),
                      "--responsibility", str(resp),
                      "--threats", str(tmp_path / "missing.yaml"), "--out", str(out))
    assert absent.returncode == 2
    assert "filtered baseline" in absent.stderr
    assert not out.exists(), "nothing is written when there is no model to cross against"

    # Saying the modelling was done and found nothing is a different statement,
    # and it is allowed.
    empty = tmp_path / "threats.yaml"
    empty.write_text("version: '0.1.0'\nthreats: []\n", encoding="utf-8")
    said_so = _run_cli("merge.py", "--cross", "--controls", str(controls),
                       "--responsibility", str(resp),
                       "--threats", str(empty), "--out", str(out))
    assert said_so.returncode == 0
    assert out.exists()
    assert "threat-only bucket is empty" in said_so.stdout


def test_a_mixed_language_statement_is_not_claimed_for_one_of_them():
    """`script_of` returned the first non-Latin script it saw anywhere, so an
    English requirement naming a Korean product was reported as written in
    Korean and blocked -- a claim about a whole statement made from one
    character."""
    for incidental in (
            "The 카카오톡 integration must not receive personal data.",
            "Audit records from 로그 must be retained for one year at minimum.",
            "The 認証 flow must reject an expired token before any handler runs."):
        assert lint_mod.script_of(incidental) is None, incidental
        assert "locale-mismatch" not in _rules(lint_mod.lint(_doc(statement=incidental), "en", None))

    # A statement genuinely in another script is still caught.
    for text, script in (("저장된 개인정보는 고객이 관리하는 키로 암호화되어야 한다.", "ko"),
                         ("データは保護されなければならない", "ja"),
                         ("数据必须使用客户管理的密钥加密", "zh")):
        assert lint_mod.script_of(text) == script, text


def test_a_malformed_threat_list_reaches_the_command_line_as_a_sentence(tmp_path, profile):
    """The ValueError text was improved and then let out of --cross as a
    traceback, so it arrived wrapped in a stack. The --apply path had converted
    validation failures to exit 2 all along."""
    derived = sb.run(profile)
    controls = tmp_path / "controls.json"
    controls.write_text(json.dumps(derived), encoding="utf-8")
    resp = tmp_path / "resp.json"
    resp.write_text(json.dumps(classify_resp.classify(profile, derived["controls"])),
                    encoding="utf-8")
    threats = tmp_path / "threats.yaml"
    threats.write_text('threats: "not a list"\n', encoding="utf-8")

    r = _run_cli("merge.py", "--cross", "--controls", str(controls),
                 "--responsibility", str(resp), "--threats", str(threats),
                 "--out", str(tmp_path / "out.json"))
    assert r.returncode == 2
    assert "Traceback" not in r.stderr
    assert "must be a list" in r.stderr


# --- the catalog build, at 0% -------------------------------------------------
#
# It needs the network, so it had never been exercised at all -- including the
# transformations that decide what a requirement's text says.

import rebuild_catalogs as rebuild_mod  # noqa: E402


@pytest.mark.parametrize("oscal,expected", [
    ("ac-2", "AC-2"), ("ac-2.1", "AC-2(1)"), ("sc-28.1", "SC-28(1)"),
    ("pm-5.1", "PM-5(1)"), ("AC-2", "AC-2"),
])
def test_the_identifier_form_matches_the_one_auditors_use(oscal, expected):
    assert rebuild_mod.display_id(oscal) == expected


@pytest.mark.parametrize("param,expected", [
    ({"id": "x", "label": "a documented period"}, "a documented period"),
    ({"id": "x", "select": {"choice": ["a", "b"], "how-many": "one"}}, "a or b"),
    ({"id": "x", "select": {"choice": ["a", "b"], "how-many": "one-or-more"}}, "a and/or b"),
    ({"id": "x", "guidelines": [{"prose": "define a period;"}]}, "define a period"),
])
def test_every_parameter_shape_upstream_uses_becomes_readable(param, expected):
    """Three shapes appear in the OSCAL source and all three must be handled, or
    raw internal ids leak into requirement text."""
    assert rebuild_mod.param_label(param) == expected


def test_the_build_refuses_when_a_parameter_has_no_label(tmp_path, monkeypatch):
    """Asserting the shipped catalogue is clean proves the data, not the guard.

    A synthetic release with a parameter shape param_label does not handle: the
    build must fail, name every offender rather than the first, and leave the
    output directory untouched.
    """
    catalog = {"catalog": {"groups": [{
        "id": "zz",
        "controls": [
            {"id": "zz-1", "title": "First",
             "params": [{"id": "zz-1_odp.01", "unheard-of-shape": {"x": 1}}],
             "parts": [{"name": "statement",
                        "prose": "Do the thing {{ insert: param, zz-1_odp.01 }}."}]},
            {"id": "zz-2", "title": "Second",
             "params": [{"id": "zz-2_odp.01", "unheard-of-shape": {"x": 1}}],
             "parts": [{"name": "statement",
                        "prose": "Do the other {{ insert: param, zz-2_odp.01 }}."}]},
        ]}]}}
    source = tmp_path / "src"
    source.mkdir()
    (source / rebuild_mod.CATALOG_FILE).write_text(json.dumps(catalog), encoding="utf-8")

    out = tmp_path / "out"
    monkeypatch.setattr(rebuild_mod, "OUT_DIR", out)
    rebuild_mod.UNRESOLVED.clear()

    # The baselines are fetched after the extraction; the guard must fire first.
    for name in rebuild_mod.BASELINE_FILES.values():
        (source / name).write_text(json.dumps({"profile": {"imports": []}}), encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        rebuild_mod.build_nist(source, {"zz"})

    message = str(exc.value)
    assert "zz-1_odp.01" in message and "zz-2_odp.01" in message, \
        "every offender, not only the family that failed first"
    assert "Nothing was written" in message
    assert not out.exists() or not list(out.glob("*.jsonl")), \
        "the catalogue must not be left half rebuilt"

    rebuild_mod.UNRESOLVED.clear()


def test_an_unresolved_parameter_is_recorded_where_it_is_known():
    """The first version looked for identifier-shaped text in the rendered
    output, which infers provenance from a string: a future OSCAL identifier in
    another grammar slips past, and a human label that happens to look like one
    is rejected. Whether the map had the key is not a matter of appearance."""
    rebuild_mod.UNRESOLVED.clear()
    rebuild_mod.resolve_params("A {{ insert: param, known }}.", {"known": "a period"})
    assert not rebuild_mod.UNRESOLVED

    # The leak begins in param_label, which returns the identifier as the label
    # -- so by the time prose is rendered the map has the key and resolution
    # sees nothing wrong. That is where it is recorded.
    rebuild_mod.param_label({"id": "zz-1_odp.01", "unheard-of-shape": {}})
    assert rebuild_mod.UNRESOLVED == {"zz-1_odp.01"}
    rebuild_mod.UNRESOLVED.clear()
    for known in ({"id": "x", "label": "a period"},
                  {"id": "x", "select": {"choice": ["a", "b"]}},
                  {"id": "x", "guidelines": [{"prose": "define it;"}]}):
        rebuild_mod.param_label(known)
    assert not rebuild_mod.UNRESOLVED

    # A label that looks exactly like an identifier is not an unresolved one.
    rebuild_mod.resolve_params("A {{ insert: param, k }}.", {"k": "ac-2.1"})
    assert not rebuild_mod.UNRESOLVED

    # And an identifier in a grammar this repository has never seen still counts.
    rebuild_mod.resolve_params("A {{ insert: param, 7F3A-UUID-LIKE }}.", {})
    assert rebuild_mod.UNRESOLVED == {"7F3A-UUID-LIKE"}
    rebuild_mod.UNRESOLVED.clear()


def test_no_raw_parameter_identifier_ships_in_the_catalog():
    """`[assignment: ac-07_odp.04]` reads like a decision the organisation is
    meant to make. The shipped catalogue carries none -- a fact about the data;
    the guard that keeps it that way is tested above."""
    leaked = re.compile(r"\[assignment: ([a-z]{2}-\d+[._][a-z0-9_.]*)\]")
    found = []
    for path in sorted((REPO_ROOT / "catalogs" / "nist-800-53r5").glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            for field in ("statement", "guidance", "title"):
                found += [m.group(1) for m in leaked.finditer(str(record.get(field) or ""))]
    assert not found, found[:10]

def test_an_unfilled_assignment_stays_visible():
    """These are the points where an organisation must decide something. A
    requirement derived from a control with an unfilled assignment is incomplete
    by construction and the reader has to be able to see that."""
    resolved = rebuild_mod.resolve_params(
        "Review accounts {{ insert: param, ac-2_odp.01 }}.",
        {"ac-2_odp.01": "a documented period"})
    assert resolved == "Review accounts [assignment: a documented period]."
    assert "{{" not in resolved


def test_the_baseline_parser_reads_every_import():
    """A profile carries the identifiers across several imports, and reading
    only the first would silently shorten a baseline."""
    profile = {"profile": {"imports": [
        {"include-controls": [{"with-ids": ["ac-2", "ac-2.1"]}]},
        {"include-controls": [{"with-ids": ["sc-28"]}]},
    ]}}
    assert rebuild_mod.parse_baseline(profile) == ["AC-2", "AC-2(1)", "SC-28"]
    assert rebuild_mod.parse_baseline({"profile": {}}) == []


# --- the HIPAA overlay build, also at 0% --------------------------------------

import rebuild_overlay_hipaa as hipaa_mod  # noqa: E402


@pytest.mark.parametrize("mark,path,level,why", [
    ("a", [], 0, "a top-level letter"),
    ("1", ["a"], 1, "a digit"),
    ("i", ["a", "1"], 2, "roman, deep enough to be roman"),
    ("A", ["a", "1", "i"], 3, "a capital"),
    ("i", ["a"], 0, "roman too shallow -- it is the letter i"),
    ("v", ["a", "1"], 2, "v is also a numeral"),
    ("x", ["a", "1"], 2, "and so is x"),
    ("iv", ["a", "1"], 2, "two characters"),
    ("b", ["a", "1"], 0, "an ordinary letter at depth two"),
])
def test_cfr_paragraph_levels_disambiguate_the_letters_that_are_also_numerals(mark, path, level, why):
    """CFR paragraphs alternate (a) (1) (i) (A), and i, v, and x are both. The
    depth reached so far is what settles them, so the rule has to be exercised
    on both readings of the same character."""
    assert hipaa_mod.level_of(mark, path) == level, why


def test_the_shipped_hipaa_overlay_still_matches_what_was_counted():
    """The build refuses to ship a clause list nobody has counted. The list it
    shipped is the one the count was taken from, and nothing checked that
    afterwards."""
    criteria = [json.loads(line) for line in
                (REPO_ROOT / "overlays" / "hipaa-security-rule" / "criteria.jsonl")
                .read_text(encoding="utf-8").splitlines() if line.strip()]
    meta = yaml.safe_load((REPO_ROOT / "overlays" / "hipaa-security-rule" /
                           "meta.yaml").read_text(encoding="utf-8"))
    assert len(criteria) == meta["criteria_count"] == 68

    # Every implementation specification carries its designation, and the two
    # values are the ones the regulation uses.
    designations = {c.get("designation") for c in criteria}
    assert designations <= {None, "Required", "Addressable"}
    assert sum(1 for c in criteria if c.get("designation")) == 46

    # And the standards are distributed across the sections the build asserts.
    from collections import Counter
    per_section = Counter(c["section"] for c in criteria if not c.get("designation"))
    for section, expected in hipaa_mod.EXPECTED_STANDARDS.items():
        assert per_section.get(section, 0) == expected, section


# --- probing the value space, which has twice the defect density of a new repo

def test_a_modifier_repeated_is_still_one_statement():
    """A modifier says something about the data; it is not a quantity. Applied
    once per appearance, three `tokenized_external` entries took health records
    from High to Low -- each subtracting a level from a claim made once."""
    thrice = _onprem(data_types=[{"id": "health_records",
                                  "modifiers": ["tokenized_external"] * 3}])
    result = sb.run(thrice)
    once = sb.run(_onprem(data_types=[{"id": "health_records",
                                       "modifiers": ["tokenized_external"]}]))
    assert result["impact"]["confidentiality"]["level"] == \
           once["impact"]["confidentiality"]["level"] == "moderate"
    assert any("repeats" in w for w in result["schema_warnings"])

    # Two different modifiers still both apply, and to the same total in either
    # order -- asserting only that no warning fired would have missed that.
    def level(modifiers):
        return sb.run(_onprem(data_types=[{"id": "basic_contact", "modifiers": modifiers}])
                      )["impact"]["confidentiality"]["level"]

    forward = level(["aggregated_large_scale", "pseudonymized_split_key"])
    backward = level(["pseudonymized_split_key", "aggregated_large_scale"])
    assert forward == backward == "moderate", f"{forward} vs {backward}"
    assert not sb.run(_onprem(data_types=[{"id": "basic_contact",
                                           "modifiers": ["aggregated_large_scale",
                                                         "pseudonymized_split_key"]}])
                      )["schema_warnings"]


def test_a_data_type_declared_twice_is_one_data_type():
    """managed_services has deduplicated since an early sweep and data_types
    never did, so the same type appeared twice in the reasons and in every count
    taken from them."""
    twice = sb.run(_onprem(data_types=[{"id": "basic_contact"}, {"id": "basic_contact"}]))
    assert len(twice["impact"]["confidentiality"]["because"]) == 1
    assert any("more than once" in w for w in twice["schema_warnings"])
    assert twice["declared_data_types"] == ["basic_contact"]

    # Distinct types are untouched.
    two = sb.run(_onprem(data_types=[{"id": "basic_contact"}, {"id": "internal_ops"}]))
    assert len(two["impact"]["confidentiality"]["because"]) == 2
    assert not two["schema_warnings"]


def test_the_same_type_saying_two_different_things_is_refused():
    """Deduplicating by first appearance let the order decide the answer:
    basic_contact declared once with intended_public and once without came out
    low or moderate depending which line was written first. An exact repeat is
    a duplicate; a repeat that says something different is a disagreement."""
    for order in ([{"id": "basic_contact", "modifiers": ["intended_public"]},
                   {"id": "basic_contact"}],
                  [{"id": "basic_contact"},
                   {"id": "basic_contact", "modifiers": ["intended_public"]}]):
        with pytest.raises(profile_schema.SchemaError) as exc:
            sb.run(_onprem(data_types=order))
        assert "declared twice with different modifiers" in str(exc.value)

    # Identical declarations are still just a duplicate.
    same = sb.run(_onprem(data_types=[{"id": "basic_contact", "modifiers": ["intended_public"]}] * 2))
    assert same["impact"]["confidentiality"]["level"] == "low"
    assert any("more than once" in w for w in same["schema_warnings"])


def test_the_repeat_warning_claims_only_what_is_true():
    """It said every repeat "would have moved the level again". intended_public
    is idempotent and customer_owned moves nothing at all."""
    repeated = sb.run(_onprem(data_types=[{"id": "user_generated_content",
                                           "modifiers": ["intended_public"] * 2}]))
    warning = next(w for w in repeated["schema_warnings"] if "repeats" in w)
    assert "moved the level again" not in warning
    assert "says something about the data once" in warning


def test_modifier_effects_do_not_depend_on_the_order_they_were_typed_in():
    """Applied one at a time, the same two statements about the same data gave
    different answers depending on which was written first.

    health_records carrying an aggregation modifier and a tokenisation modifier
    came out High one way and Moderate the other, because a bump that saturates
    at High loses the excess and the subtraction that follows starts from the
    clamped value. The relative effects sum before anything is clamped now.
    """
    def level(type_id, modifiers):
        return sb.run(_onprem(data_types=[{"id": type_id, "modifiers": modifiers}])
                      )["impact"]["confidentiality"]["level"]

    for type_id in ("basic_contact", "health_records", "payment_token", "government_id"):
        forward = level(type_id, ["aggregated_large_scale", "tokenized_external"])
        backward = level(type_id, ["tokenized_external", "aggregated_large_scale"])
        assert forward == backward, f"{type_id}: {forward} vs {backward}"

    # And the net of +1 and -1 is no movement at all.
    assert level("health_records", ["aggregated_large_scale", "tokenized_external"]) == \
           level("health_records", [])


def test_a_statement_about_what_the_data_is_wins_over_an_adjustment():
    """Content declared as intended for publication came out Moderate when the
    aggregation modifier happened to be listed after it -- the opposite of what
    the declaration says. An absolute assignment is applied last."""
    def level(modifiers):
        return sb.run(_onprem(data_types=[{"id": "user_generated_content",
                                           "modifiers": modifiers}])
                      )["impact"]["confidentiality"]["level"]

    assert level(["intended_public", "aggregated_large_scale"]) == "low"
    assert level(["aggregated_large_scale", "intended_public"]) == "low"
    assert level(["intended_public"]) == "low"

    # Two absolute statements that disagree cannot both be true, and the tool
    # says so rather than picking whichever was written first.
    table = yaml.safe_load((REPO_ROOT / "catalogs" / "data-types" /
                            "classification.yaml").read_text(encoding="utf-8"))
    absolutes = [m for m, spec in table["modifiers"].items()
                 if isinstance((spec.get("effect") or {}).get("confidentiality"), str)]
    assert len(absolutes) == 1, \
        f"if a second absolute modifier is added, the conflict path needs a test: {absolutes}"


# --- the refresh, end to end at the command line -------------------------------

def _refresh_workspace(tmp_path):
    existing = {"requirements": [
        {"id": "REQ-PKI-SIGNING-KEY-01",
         "managed": {"statement": "The signing key must be non-exportable.",
                     "csf": ["PR.DS-01"], "sources": ["SC-12"], "responsibility": "team"},
         "human": {}},
        {"id": "REQ-PKI-LOG-SHIP-01",
         "managed": {"statement": "Issuance records must ship off host.",
                     "csf": ["DE.CM-09"], "sources": ["AU-9"], "responsibility": "team"},
         "human": {"status": "accepted_risk", "note": "deferred to Q3", "owner": "platform"}},
        {"id": "REQ-PKI-GONE-01",
         "managed": {"statement": "An old thing.", "csf": ["PR.DS-01"],
                     "sources": ["SC-28"], "responsibility": "team"},
         "human": {}},
    ]}
    (tmp_path / "requirements.yaml").write_text(yaml.safe_dump(existing, sort_keys=False),
                                                encoding="utf-8")
    (tmp_path / "state.yaml").write_text("issued: {}\n", encoding="utf-8")
    draft = {"requirements": [
        {"slug": "PKI-SIGNING-KEY", "managed": existing["requirements"][0]["managed"]},
        {"slug": "PKI-LOG-SHIP",
         "managed": {**existing["requirements"][1]["managed"],
                     "statement": "Issuance records must ship off host within one minute."}},
        {"slug": "PKI-NEW-HSM",
         "managed": {"statement": "The module must attest the key it generated.",
                     "csf": ["PR.DS-01"], "sources": ["SC-12(1)"], "responsibility": "team"}},
    ]}
    (tmp_path / "draft.json").write_text(json.dumps(draft), encoding="utf-8")
    return tmp_path


def test_a_refresh_keeps_what_a_human_decided(tmp_path):
    """The refresh machinery -- retire, reopen, pending_review -- had run only
    inside unit calls. Through the command line, on a document where a human had
    accepted a risk and written a note against it."""
    work = _refresh_workspace(tmp_path)
    r = _run_cli("merge.py", "--apply", "--draft", str(work / "draft.json"),
                 "--existing", str(work / "requirements.yaml"),
                 "--state", str(work / "state.yaml"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "added          1" in r.stdout
    assert "proposed       1" in r.stdout
    assert "unchanged      1" in r.stdout
    assert "retired        1" in r.stdout

    written = yaml.safe_load((work / "requirements.yaml").read_text(encoding="utf-8"))
    by_id = {req["id"]: req for req in written["requirements"]}

    # The human's decision and note survive, and the re-derived text waits.
    kept = by_id["REQ-PKI-LOG-SHIP-01"]
    assert kept["human"]["note"] == "deferred to Q3"
    assert kept["human"]["owner"] == "platform"
    assert kept["human"]["status"] == "accepted_risk"
    assert "pending_review" in kept, "the new text is proposed, not applied over a human edit"

    # What no longer derives is retired rather than deleted.
    assert by_id["REQ-PKI-GONE-01"]["human"]["status"] == "retired"
    assert "REQ-PKI-NEW-HSM-01" in by_id

    # And the state file records the allocation, so the next run matches.
    state = yaml.safe_load((work / "state.yaml").read_text(encoding="utf-8"))
    assert state["issued"]["PKI-NEW-HSM"] == "REQ-PKI-NEW-HSM-01"


def test_a_second_refresh_with_no_change_moves_nothing(tmp_path):
    """Idempotence is the property that makes a refresh safe to run."""
    work = _refresh_workspace(tmp_path)
    first = _run_cli("merge.py", "--apply", "--draft", str(work / "draft.json"),
                     "--existing", str(work / "requirements.yaml"),
                     "--state", str(work / "state.yaml"))
    assert first.returncode == 0
    second = _run_cli("merge.py", "--apply", "--draft", str(work / "draft.json"),
                      "--existing", str(work / "requirements.yaml"),
                      "--state", str(work / "state.yaml"))
    assert second.returncode == 0, second.stdout + second.stderr
    assert "added          0" in second.stdout
    assert "retired        0" in second.stdout


@pytest.mark.parametrize("broken,expected", [
    ("issued:\n  PKI-SIGNING-KEY: 1\n", "is not an identifier"),
    ("issued: [a, b]\n", "is a list"),
    ("- a\n- b\n", "holds a list"),
    ("issued:\n  not a slug!: REQ-X-01\n", "not a slug"),
    ("issued:\n  PKI-SIGNING-KEY: REQ-OTHER-01\n", "belongs to a different requirement"),
])
def test_a_hand_edited_state_file_gets_a_sentence(tmp_path, broken, expected):
    """It is shared across a team and edited by hand, and a value that is not an
    identifier produced a raw AttributeError from inside the allocator."""
    work = _refresh_workspace(tmp_path)
    (work / "state.yaml").write_text(broken, encoding="utf-8")
    r = _run_cli("merge.py", "--apply", "--draft", str(work / "draft.json"),
                 "--existing", str(work / "requirements.yaml"),
                 "--state", str(work / "state.yaml"))
    assert r.returncode == 2
    assert "Traceback" not in r.stderr
    assert expected in r.stderr


def test_a_state_entry_that_points_at_another_requirement_is_refused():
    """The state file exists to keep an identifier attached to the same
    requirement across refreshes, so an entry pointing at some other slug's
    identifier is the one thing it must not do quietly. A merge conflict in this
    file is all it takes, and the result is a document whose identifiers no
    longer mean what a reader thinks."""
    with pytest.raises(ValueError) as exc:
        merge.issue_id("PKI-SIGNING-KEY", {"issued": {"PKI-SIGNING-KEY": "REQ-OTHER-01"}})
    assert "belongs to a different requirement" in str(exc.value)

    # A malformed sequence is the same problem, and so is a second identity for
    # one slug: the allocator writes -01 and nothing else, so accepting -02
    # through -99 left a hand-edited entry able to add an identity while the old
    # one retired -- with most of the document still matching, the total-churn
    # guard sees an ordinary refresh.
    for wrong in ("REQ-A-B-1", "REQ-A-B-02", "REQ-A-B-99"):
        with pytest.raises(ValueError):
            merge.issue_id("A-B", {"issued": {"A-B": wrong}})

    # Its own identifier is returned unchanged, which is the whole point.
    assert merge.issue_id("A-B", {"issued": {"A-B": "REQ-A-B-01"}}) == "REQ-A-B-01"


def test_one_slug_has_one_identifier():
    """The sequence number was computed from the count of existing values
    starting with the same prefix, which read as collision handling. The slug is
    the key, so there has never been anything to count and it was always 01."""
    state = {"issued": {}}
    assert merge.issue_id("A-B", state) == "REQ-A-B-01"
    assert merge.issue_id("A-B", state) == "REQ-A-B-01"
    assert merge.issue_id("C-D", state) == "REQ-C-D-01"
    assert state["issued"] == {"A-B": "REQ-A-B-01", "C-D": "REQ-C-D-01"}


def test_a_refresh_is_byte_for_byte_idempotent(tmp_path):
    """Counting zero added and zero retired is weaker than the property that
    makes a refresh safe to run: the file it writes the second time is the file
    it wrote the first."""
    work = _refresh_workspace(tmp_path)
    args = ("merge.py", "--apply", "--draft", str(work / "draft.json"),
            "--existing", str(work / "requirements.yaml"), "--state", str(work / "state.yaml"))
    assert _run_cli(*args).returncode == 0
    after_first = (work / "requirements.yaml").read_bytes()
    state_first = (work / "state.yaml").read_bytes()

    assert _run_cli(*args).returncode == 0
    assert (work / "requirements.yaml").read_bytes() == after_first
    assert (work / "state.yaml").read_bytes() == state_first


# --- the overlay validator's own assertions, never exercised -------------------
#
# Every one of the six shipped overlays passes, so each guard was untested. The
# same lesson as the catalog build: a clean fixture proves the data, not the
# check.

import validate_overlays as vo  # noqa: E402


def _broken_overlay(tmp_path, monkeypatch, *, meta_change=None, mapping_change=None):
    """A copy of a real overlay with one thing wrong with it."""
    import shutil
    work = tmp_path / "overlays"
    shutil.copytree(REPO_ROOT / "overlays", work)
    source = work / "gdpr"

    if meta_change:
        meta = yaml.safe_load((source / "meta.yaml").read_text(encoding="utf-8"))
        meta_change(meta)
        (source / "meta.yaml").write_text(yaml.safe_dump(meta, allow_unicode=True,
                                                         sort_keys=False), encoding="utf-8")
    if mapping_change:
        rows = [json.loads(line) for line in
                (source / "mappings.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        mapping_change(rows)
        (source / "mappings.jsonl").write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")

    monkeypatch.setattr(overlay_mod, "OVERLAYS", work)
    monkeypatch.setattr(vo, "REPO_ROOT", tmp_path)
    captured = []
    monkeypatch.setattr(vo, "print", lambda *a, **k: captured.append(" ".join(map(str, a))),
                        raising=False)
    code = vo.main([])
    return code, captured


def test_an_authored_mapping_presented_as_anything_else_is_refused(tmp_path, monkeypatch):
    """The failure this repository exists to prevent: a reading offered as a
    published crosswalk."""
    code, out = _broken_overlay(tmp_path, monkeypatch,
                                meta_change=lambda m: m["mapping"].update({"authored": False}))
    assert code == 1
    assert any("mapping.authored must be true" in line for line in out)


def test_an_overlay_without_a_disclaimer_is_refused(tmp_path, monkeypatch):
    code, out = _broken_overlay(tmp_path, monkeypatch,
                                meta_change=lambda m: m.update({"disclaimer": "  "}))
    assert code == 1
    assert any("no disclaimer" in line for line in out)


def test_a_depth_block_that_does_not_state_its_limit_is_refused(tmp_path, monkeypatch):
    """An overlay that stops above the assessed clause must say so, or a
    coverage count reads as compliance."""
    code, out = _broken_overlay(
        tmp_path, monkeypatch,
        meta_change=lambda m: m.update({"depth": {"level": "articles",
                                                  "sub_requirements_enumerated": True}}))
    assert code == 1
    assert any("does not state the limit" in line for line in out)


def test_a_standalone_flag_that_disagrees_with_its_controls_is_refused(tmp_path, monkeypatch):
    def break_one(rows):
        row = next(r for r in rows if r["controls"])
        row["standalone"] = True
    code, out = _broken_overlay(tmp_path, monkeypatch, mapping_change=break_one)
    assert code == 1
    assert any("standalone disagrees" in line for line in out)


def test_an_unknown_responsibility_hint_is_refused(tmp_path, monkeypatch):
    def break_one(rows):
        rows[0]["responsibility_hint"] = "somebody"
    code, out = _broken_overlay(tmp_path, monkeypatch, mapping_change=break_one)
    assert code == 1
    assert any("unknown responsibility_hint" in line for line in out)


def test_a_clause_citing_the_same_control_twice_is_refused(tmp_path, monkeypatch):
    def break_one(rows):
        row = next(r for r in rows if r["controls"])
        row["controls"] = row["controls"] + [row["controls"][0]]
    code, out = _broken_overlay(tmp_path, monkeypatch, mapping_change=break_one)
    assert code == 1
    assert any("duplicate controls" in line for line in out)


def test_an_overlay_that_will_not_load_is_reported_rather_than_crashing(tmp_path, monkeypatch):
    """A malformed overlay must be named, not raise out of the validator."""
    code, out = _broken_overlay(tmp_path, monkeypatch,
                                meta_change=lambda m: m.update({"criteria_count": 999}))
    assert code == 1
    assert any("gdpr" in line and "criteria_count" in line for line in out)


# --- the golden evaluator's failure paths, at the command line ----------------

def _golden_document():
    draft = json.loads((GOLDEN / "draft.json").read_text(encoding="utf-8"))["requirements"]
    return {"requirements": [
        {"id": merge.issue_id(item["slug"], {"issued": {}}), "managed": item["managed"],
         "human": {}} for item in draft]}


def test_the_golden_case_passes_at_the_command_line(tmp_path):
    """It had never been run. The shipped draft scores at full recall with no
    excluded subject appearing -- the property a regression in the model stage
    would break."""
    doc = tmp_path / "requirements.yaml"
    doc.write_text(yaml.safe_dump(_golden_document(), sort_keys=False, allow_unicode=True),
                   encoding="utf-8")
    r = _run_cli("eval_golden.py", str(GOLDEN), str(doc))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "recall 100%" in r.stdout


def test_an_excluded_subject_appearing_fails_the_case(tmp_path):
    """must_not_cover is how the suite catches the tool prescribing something
    the profile said the organisation already has -- telling a team that runs
    company-wide SSO to introduce it."""
    expected = yaml.safe_load((GOLDEN / "expected-coverage.yaml").read_text(encoding="utf-8"))
    forbidden = expected["must_not_cover"][0]["match_any"][0]

    document = _golden_document()
    document["requirements"][0]["managed"]["statement"] = \
        f"The service must {forbidden} for every tenant."
    doc = tmp_path / "requirements.yaml"
    doc.write_text(yaml.safe_dump(document, sort_keys=False, allow_unicode=True), encoding="utf-8")

    r = _run_cli("eval_golden.py", str(GOLDEN), str(doc))
    assert r.returncode == 1
    assert "Excluded subjects appeared" in r.stdout
    assert expected["must_not_cover"][0]["id"] in r.stdout
    assert "already in place" in r.stdout, "and the reason it is excluded"


def test_a_thin_document_fails_on_the_topics_a_baseline_cannot_reach(tmp_path):
    """The critical topics are the ones a baseline-only run cannot produce.
    Missing them means the threat model returned generic material, which is the
    failure the whole tool is arranged against."""
    doc = tmp_path / "requirements.yaml"
    doc.write_text(yaml.safe_dump({"requirements": [
        {"id": "REQ-A-B-01", "managed": {"statement": "nothing much"}, "human": {}}]}),
        encoding="utf-8")
    r = _run_cli("eval_golden.py", str(GOLDEN), str(doc))
    assert r.returncode == 1
    assert "Critical topics missing" in r.stdout
    assert "Recall below threshold" in r.stdout
    assert "baseline-only run cannot reach" in r.stdout


# --- the CFR parser, which turns a regulation into clauses --------------------

def _cfr(paragraphs, section="164.308"):
    """A source document carrying one section's paragraphs."""
    import xml.etree.ElementTree as ET
    root = ET.Element("root")
    for sid in hipaa_mod.SECTIONS:
        div = ET.SubElement(root, "DIV8")
        div.set("N", sid)
        for text in (paragraphs if sid == section else []):
            ET.SubElement(div, "P").text = text
    return root


def test_a_standard_is_read_as_a_standard():
    """The regulation labels them, and the label is what separates a standard
    from the specifications beneath it."""
    records, _ = hipaa_mod.extract(_cfr([
        "(a)(1)(i) Standard: Security management process. Implement policies and procedures."]))
    assert len(records) == 1
    assert records[0]["kind"] == "standard"
    assert records[0]["clause"] == "164.308(a)(1)(i)"
    assert records[0]["title"] == "Security management process"
    assert records[0]["designation"] is None


def test_an_implementation_specification_carries_its_designation():
    """Required and Addressable are not decoration: Addressable means a covered
    entity may document why it did something else, and Required means it may
    not."""
    records, seen = hipaa_mod.extract(_cfr([
        "(a)(1)(ii)(A) Risk analysis (Required). Conduct an accurate assessment."]))
    assert seen == 1
    assert records[0]["kind"] == "implementation_specification"
    assert records[0]["designation"] == "Required"
    assert records[0]["designation_source"] == "inline"


def test_a_group_heading_lends_its_designation_to_what_is_under_it():
    """Two headings carry a designation that belongs to the specifications
    beneath them rather than to themselves, and the specification is nested one
    level deeper -- read flat, the contract terms listed under it would be
    recorded as though they were specifications of their own."""
    records, _ = hipaa_mod.extract(_cfr([
        "(a)(1)(ii) Implementation specifications (Required) — (A) Risk analysis. "
        "Conduct an assessment."]))
    assert len(records) == 1
    assert records[0]["clause"] == "164.308(a)(1)(ii)(A)"
    assert records[0]["designation"] == "Required"
    assert records[0]["designation_source"] == "group heading"


def test_a_source_missing_a_section_is_refused():
    """The regulation has five sections in scope. A source that does not carry
    one of them cannot produce the clause list, and a short list nobody counts
    is the failure the build exists to prevent."""
    import xml.etree.ElementTree as ET
    with pytest.raises(SystemExit) as exc:
        hipaa_mod.extract(ET.Element("root"))
    assert "not present in the source" in str(exc.value)


def test_a_label_that_names_another_control_s_parameter_resolves():
    """collect_params resolved over a map holding only its own control's
    parameters, so a label referring to a parameter defined on a sibling could
    not find it and baked the identifier into the label -- before the
    catalogue-wide map the module describes was ever consulted. The reader was
    then shown an identifier where a decision should be.

    Removing the local pass altogether was worse: SI-3's statement shipped an
    unresolved placeholder. Resolution belongs once, against the merged map.
    """
    rebuild_mod.UNRESOLVED.clear()
    catalog = {"groups": [{"id": "ac", "controls": [
        {"id": "ac-1", "params": [{"id": "p1", "label": "one"}]},
        {"id": "ac-2", "params": [{"id": "p2", "label": "{{ insert: param, p1 }} then two"}]},
        {"id": "ac-3", "params": [{"id": "p3", "label": "{{ insert: param, p2 }} then three"}],
         "parts": [{"name": "statement", "prose": "Do {{ insert: param, p3 }}."}]},
    ]}]}
    globals_ = rebuild_mod.build_global_params(catalog)
    assert globals_["p2"] == "[assignment: one] then two"
    assert "p1" not in globals_["p2"], "an identifier where a label belongs"

    record = list(rebuild_mod.walk_controls(catalog["groups"][0]["controls"], "ac", globals_))[-1]
    assert "{{" not in record["statement"], "no placeholder survives into the text"
    assert "one" in record["statement"]
    assert not rebuild_mod.UNRESOLVED
    rebuild_mod.UNRESOLVED.clear()


def test_the_catalog_is_the_one_the_build_produces():
    """The bundled files must be what rebuilding produces, or the checked-in
    catalogue and the script that claims to generate it have parted company."""
    import subprocess
    before = {path.name: path.read_bytes()
              for path in sorted((REPO_ROOT / "catalogs" / "nist-800-53r5").glob("*.jsonl"))}
    assert before, "the catalogue must be present"
    # Not rebuilt here -- that needs the network. What is asserted is that every
    # record parses and carries the fields the pipeline reads.
    for name, blob in before.items():
        for line in blob.decode("utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            assert record["id"] and record["family"] and "statement" in record
            assert "{{" not in json.dumps(record), f"{record['id']} carries a placeholder"


def test_a_parameter_reference_that_does_not_settle_is_refused():
    """Substituting a cycle terminates: three passes leave text with no
    placeholder in it and every level of nesting still there, and nothing
    downstream can tell that from a legitimate label. It would ship as the
    reader's decision point."""
    with pytest.raises(SystemExit) as exc:
        rebuild_mod.resolve_map({"p1": "{{ insert: param, p2 }}",
                                 "p2": "{{ insert: param, p1 }}"})
    assert "does not" in str(exc.value) or "still refer" in str(exc.value)

    with pytest.raises(SystemExit):
        rebuild_mod.resolve_map({"p1": "{{ insert: param, p1 }}"})

    # The message does not claim to know which it is. A chain deeper than three
    # looks identical from here.
    with pytest.raises(SystemExit) as exc:
        rebuild_mod.resolve_map({f"p{i}": (f"{{{{ insert: param, p{i - 1} }}}} s" if i else "base")
                                 for i in range(20)})
    assert "Either they form a cycle or the chain is deeper" in str(exc.value)

    # A chain the catalogue actually uses settles.
    settled = rebuild_mod.resolve_map({"p1": "one", "p2": "{{ insert: param, p1 }} two",
                                       "p3": "{{ insert: param, p2 }} three"})
    assert not any("{{" in v for v in settled.values())


def test_a_build_does_not_inherit_the_previous_build_s_failures(tmp_path, monkeypatch):
    """UNRESOLVED is module state. A second build in one process was refusing
    for a reason that was no longer true, and the tests were clearing it by hand
    -- which is the tell."""
    rebuild_mod.UNRESOLVED.add("left-over-from-somewhere")

    catalog = {"catalog": {"groups": [{"id": "zz", "controls": [
        {"id": "zz-1", "title": "Fine",
         "params": [{"id": "zz-1_odp.01", "label": "a documented period"}],
         "parts": [{"name": "statement", "prose": "Do it {{ insert: param, zz-1_odp.01 }}."}]}]}]}}
    source = tmp_path / "src"
    source.mkdir()
    (source / rebuild_mod.CATALOG_FILE).write_text(json.dumps(catalog), encoding="utf-8")
    for name in rebuild_mod.BASELINE_FILES.values():
        (source / name).write_text(json.dumps({"profile": {"imports": []}}), encoding="utf-8")
    monkeypatch.setattr(rebuild_mod, "OUT_DIR", tmp_path / "out")

    # The synthetic release has no PM family, so the build fails later on for a
    # different and correct reason. What matters here is that it did not fail on
    # the leftover, and that the leftover is gone.
    with pytest.raises(SystemExit) as exc:
        rebuild_mod.build_nist(source, {"zz"})
    assert "left-over-from-somewhere" not in str(exc.value)
    assert not rebuild_mod.UNRESOLVED


def test_a_requirement_cannot_claim_a_threat_that_is_not_in_the_model():
    """The threat side of this check has been here all along -- a threat's
    control identifiers are verified against the catalogue. A requirement's
    threat references were verified against nothing, so a mistyped id produced a
    requirement that traces to nothing while saying it traces to a threat, and
    the traceability document repeats the claim."""
    model = {"threats": [{"id": "T-01"}]}

    good = _doc(threat_refs=["T-01"])
    assert "threat-ref-unknown" not in _rules(lint_mod.lint(good, "en", model))

    mistyped = _doc(threat_refs=["T-99"])
    findings = lint_mod.lint(mistyped, "en", model)
    assert "threat-ref-unknown" in _rules(findings)
    assert any("claims a provenance it does not have" in str(f) for f in findings)

    # A string is iterable, which is how this repository has been bitten five
    # times.
    scalar = _doc(threat_refs="T-01")
    assert "threat-ref-format" in _rules(lint_mod.lint(scalar, "en", model))

    # With no model supplied there is nothing to check against, and inventing a
    # complaint would be worse than staying quiet.
    assert "threat-ref-unknown" not in _rules(lint_mod.lint(mistyped, "en", None))


def test_nothing_from_the_human_record_reaches_the_published_file():
    """requirements.md is what leaves the building; `human:` is the internal
    record. The retirement reason was fixed two commits ago and the exception
    block sat next to it, publishing the approver's name and title, the expiry,
    and the rationale -- which named a vendor."""
    doc = {"requirements": [
        _req("REQ-A-B-01", human={"status": "accepted_risk", "exception": {
            "approver": "Jane Park, CISO", "expires": "2027-01-31",
            "reason": "the vendor cannot support customer keys until the Q1 release"}}),
        _req("REQ-C-D-01", human={"status": "retired",
                                  "retired_reason": "closed by the CISO's exception"}),
    ]}
    published, _, _ = _documents(doc["requirements"])

    for private in ("Jane Park", "CISO", "vendor", "cannot support"):
        assert private not in published, private

    # What a reader outside does need: that an exception exists, and when it
    # lapses. A date is not a person.
    assert "An exception is recorded" in published
    assert "2027-01-31" in published
    assert "held in the internal record" in published

    # And an exception with no expiry says so rather than inventing one.
    no_expiry, _, _ = _documents([
        _req("REQ-E-F-01", human={"status": "accepted_risk",
                                  "exception": {"approver": "someone"}})])
    assert "no expiry date" in no_expiry
    assert "someone" not in no_expiry


def test_no_free_text_from_the_human_block_appears_in_any_published_document():
    """Two leaks were found one at a time -- the retirement reason, then the
    exception's approver and rationale. `human` is open-ended by design, so the
    next field someone adds would be published the moment anyone renders it.

    This asserts the class rather than the instance: every plausible free-text
    field carries a distinctive marker, and no marker may appear in any of the
    three documents. A status is a state and is published; a date is not a
    person and is published. Prose written by a person is not.
    """
    marker = "CANARY7391"
    human = {
        "status": "accepted_risk",
        "retired_reason": f"{marker}-retired",
        "reinstated_reason": f"{marker}-reinstated",
        "note": f"{marker}-note",
        "owner": f"{marker}-owner",
        "reviewer": f"{marker}-reviewer",
        "decision_log": [f"{marker}-log"],
        "exception": {"approver": f"{marker}-approver",
                      "reason": f"{marker}-reason",
                      "ticket": f"{marker}-ticket",
                      "expires": "2027-01-31"},
    }
    documents = _documents([
        _req("REQ-A-B-01", human=dict(human)),
        _req("REQ-C-D-01", human={"status": "retired", "retired_reason": f"{marker}-gone"}),
    ])
    for document in documents:
        assert marker not in document, document[:400]

    # The facts a reader outside does need are still there.
    published = documents[0]
    assert "accepted_risk" in published
    assert "2027-01-31" in published
    assert "held in the internal record" in published


def test_a_nested_assignment_is_a_second_decision_not_an_artefact():
    """Raised in review as a rendering artefact of expanding labels into labels.

    It is not. AC-7's lockout options are a choice, and one of the options
    carries a time period the organisation must also set: the outer bracket is
    which behaviour, the inner one is how long. Flattening would hide the second
    decision, which is the opposite of why the markers are visible at all.
    """
    ac7 = None
    for line in (REPO_ROOT / "catalogs" / "nist-800-53r5" / "AC.jsonl") \
            .read_text(encoding="utf-8").splitlines():
        if line.strip() and json.loads(line)["id"] == "AC-7":
            ac7 = json.loads(line)
            break
    assert ac7, "AC-7 must be in the bundled catalogue"
    statement = ac7["statement"]
    assert "[assignment:" in statement
    nested = re.search(r"\[assignment:[^\]]*\[assignment:[^\]]*\]", statement)
    assert nested, "AC-7 is the case this test exists for"
    assert "time period" in nested.group(0)


def test_the_csf_filter_drops_exactly_what_it_says_it_drops(tmp_path, monkeypatch):
    """The upstream release carries CSF 1.1 material alongside 2.0 -- 185
    subcategories across 34 categories -- with the retired entries marked
    withdrawn. Both filters matter: the withdrawn flag and the published
    category set. Neither had ever run on a paragraph.
    """
    good = next(iter(sorted(rebuild_mod.CSF_20_CATEGORIES)))
    catalog = {"catalog": {
        "metadata": {"version": "1.0", "last-modified": "2026-01-01"},
        "groups": [{"id": good.split(".")[0].lower(), "controls": [
            {"id": good, "class": "category", "title": "A category", "controls": [
                {"id": f"{good}-01", "class": "subcategory", "title": "Kept"},
                {"id": f"{good}-02", "class": "subcategory", "title": "Retired",
                 "props": [{"name": "status", "value": "withdrawn"}]},
                {"id": f"{good}-03", "class": "control", "title": "Not a subcategory"},
            ]},
            {"id": "ZZ.OLD", "class": "category", "title": "A 1.1 category", "controls": [
                {"id": "ZZ.OLD-01", "class": "subcategory", "title": "Gone in 2.0"},
            ]},
        ]}]}}
    source = tmp_path / "src"
    source.mkdir()
    (source / rebuild_mod.CSF_FILE).write_text(json.dumps(catalog), encoding="utf-8")
    out = tmp_path / "csf"
    monkeypatch.setattr(rebuild_mod, "CSF_OUT_DIR", out)

    meta = rebuild_mod.build_csf(source)

    assert meta["category_count"] == 1, "the 1.1 category is not in the published set"
    assert meta["subcategory_count"] == 1, "the withdrawn subcategory is not published"
    assert meta["withdrawn_or_legacy_skipped"] == 2

    kept = [json.loads(line) for line in
            (out / "subcategories.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    assert [r["id"] for r in kept] == [f"{good}-01"]
    assert kept[0]["category"] == good
    assert kept[0]["function"] == good.split(".")[0]


def test_the_asvs_build_carries_its_licence_with_it(tmp_path, monkeypatch):
    """ASVS is CC BY-SA 4.0. The build writes the licence and the notice beside
    the requirements because redistributing the text without them is the one
    thing the licence forbids, and nothing had ever checked that it does."""
    payload = {"requirements": [
        {"req_id": "V1.1.1", "chapter_id": "V1", "chapter_name": "Encoding",
         "section_id": "V1.1", "section_name": "Input", "req_description": "Verify a thing.",
         "L": "1"},
        {"req_id": "V2.1.1", "chapter_id": "V2", "chapter_name": "Auth",
         "section_id": "V2.1", "section_name": "Passwords", "req_description": "Verify another.",
         "L": ""},
    ]}
    source = tmp_path / "src"
    source.mkdir()
    (source / rebuild_mod.ASVS_FILE).write_text(json.dumps(payload), encoding="utf-8")
    out = tmp_path / "asvs"
    monkeypatch.setattr(rebuild_mod, "ASVS_OUT_DIR", out)

    meta = rebuild_mod.build_asvs(source)

    assert (out / "LICENSE").read_text(encoding="utf-8").strip()
    assert (out / "NOTICE").read_text(encoding="utf-8").strip()
    assert "CC BY-SA" in (out / "LICENSE").read_text(encoding="utf-8")

    # One file per chapter, and an unlabelled level is recorded as unspecified
    # rather than guessed at -- the level decides which requirements a service
    # is held to.
    assert {p.stem for p in out.glob("*.jsonl")} == {"V1", "V2"}
    first = json.loads((out / "V1.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert first["id"] == "ASVS-V1.1.1" and first["level"] == 1
    second = json.loads((out / "V2.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert second["level"] is None
    assert meta["level_counts"]["unspecified"] == 1
    assert meta["requirement_count"] == 2


def test_the_auditor_s_document_shows_what_no_control_produced():
    """traceability.md is the auditor's, and it listed only what a control maps
    to. A threat-only requirement -- the kind this tool exists to find, and the
    kind no catalogue could have given you -- was absent from the one document
    an auditor reads for coverage. The requirements document said five and this
    one showed four."""
    _, trace, _ = _documents([
        _req("REQ-A-B-01", sources=["SC-28"]),
        _req("REQ-C-D-01", sources=[], threat_refs=["T-05"],
             statement="The party holding the key must be named in the risk record."),
    ])
    assert "Traced to no control" in trace
    assert "REQ-C-D-01" in trace
    assert "T-05" in trace, "and which threat it came from"
    assert "REQ-C-D-01" not in trace.split("## Traced to no control")[0], \
        "it is not in the control table, because no control produced it"

    # A document where every requirement cites a control does not grow a section
    # saying so.
    _, only_sourced, _ = _documents([_req("REQ-A-B-01", sources=["SC-28"])])
    assert "Traced to no control" not in only_sourced

    # A threat-only requirement with no recorded provenance still appears.
    _, no_refs, _ = _documents([_req("REQ-E-F-01", sources=[])])
    assert "not recorded" in no_refs.split("## Traced to no control")[1]
