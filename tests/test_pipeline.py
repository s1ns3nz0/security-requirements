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
    ids = {item["id"] for item in derived["uncovered_regulations"]}
    assert "gdpr_personal_data" not in ids
    assert "pipa_general" in ids


def test_gdpr_fires_for_eu_users(profile):
    eu = copy.deepcopy(profile)
    eu["declared"]["user_regions"] = ["DE"]
    ids = {item["id"] for item in sb.run(eu)["uncovered_regulations"]}
    assert "gdpr_personal_data" in ids


def test_pci_always_fires_regardless_of_region(profile):
    card = copy.deepcopy(profile)
    card["declared"]["data_types"].append({"id": "payment_card_raw"})
    card["declared"]["user_regions"] = ["BR"]
    ids = {item["id"] for item in sb.run(card)["uncovered_regulations"]}
    assert "pci_dss" in ids


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
