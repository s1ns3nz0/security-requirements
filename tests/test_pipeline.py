"""Regression tests for the deterministic half of the pipeline.

Everything covered here is a lookup or an arithmetic step. The model-dependent
half -- threat modeling and requirement authoring -- is scored separately by
scripts/eval_golden.py, because there is no fixed answer to assert against.

Several tests exist because the week-1 tracer bullet found the bug they now
guard. Those are marked.
"""

from __future__ import annotations

import copy
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
    triggered = uncovered | {item["trigger"] for item in derived["overlay_triggers"]}
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
                 | {t["trigger"] for t in result["overlay_triggers"]})
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
                 | {t["trigger"] for t in result["overlay_triggers"]})
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
                 | {t["trigger"] for t in result["overlay_triggers"]})
    assert "pipa_general" in triggered


@pytest.mark.parametrize("written", ["ap-northeast-2", "AP-NORTHEAST-2", " ap-northeast-2 "])
def test_region_spelling_does_not_lose_cross_border(profile, written):
    p = copy.deepcopy(profile)
    p["inferred"]["region_storage"] = written
    assert sb.run(p)["cross_border"]["storage_country"] == "KR"


@pytest.mark.parametrize("written", [["sso"], ["SSO"], "sso", [" SSO "]])
def test_org_control_spelling_keeps_its_annotations(profile, written):
    p = copy.deepcopy(profile)
    p["declared"]["existing_org_controls"] = written
    result = classify_resp.classify(p, ["AC-2", "AU-6"])
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
    assert all(f["from_data_type"] and f["label"] for f in forced)


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
    item = next(i for i in crossed["items"] if i["control"] == "AC-7")
    assert item["priority"] == "medium"


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
    assert any("ZZ-9" in p for p in result["problems"])


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


def test_an_overlay_sees_the_privacy_baseline(profile):
    """Judging a privacy regime against the security baseline alone reports the
    tool's own blind spot as the service's gap."""
    loaded = overlay_mod.load("gdpr")
    derived = sb.run(profile)
    without = overlay_mod.evaluate(loaded, derived["controls"])
    with_privacy = overlay_mod.evaluate(
        loaded, derived["controls"], privacy_controls=derived["privacy_controls"])
    assert len(with_privacy["covered"]) > len(without["covered"])
    assert len(with_privacy["uncovered"]) < len(without["uncovered"])


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


def test_management_system_clauses_fall_outside_a_security_baseline(profile):
    """SP 800-53B allocates the PM family to no security baseline, so the ISO
    clauses report as unreached. That is the finding, not a defect: a derivation
    does not build a management system."""
    loaded = overlay_mod.load("iso-27001")
    derived = sb.run(profile)
    result = overlay_mod.evaluate(loaded, derived["controls"])
    unreached = {r["clause"] for r in result["uncovered"]} | {r["clause"] for r in result["partial"]}
    assert any(c.startswith("Clause") for c in unreached)


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
    """PM-1 and PM-2 are in no baseline this tool resolves, so the leadership
    clauses of three regimes can never report as reached. Listing them beside
    the clauses a service simply has not covered puts a property of the tool
    into the reader's gap list."""
    derived = sb.run(profile)
    result = overlay_mod.evaluate(overlay_mod.load("pipa-isms-p"), derived["controls"])
    unreachable = {r["clause"] for r in result["unreachable"]}
    assert {"1.1.1", "2.1.2"} <= unreachable
    assert not (unreachable & {r["clause"] for r in result["uncovered"]})

    rendered = overlay_mod.render(result, "test")
    assert "can never report as reached" in rendered


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
