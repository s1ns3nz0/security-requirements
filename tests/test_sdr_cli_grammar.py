"""CLI-grammar specification for the security-design-review extension (N33-N35).

These tests describe the two subcommands the plan adds to the *existing*
``risk.argument_parser()`` (``risk.py:3277``) — ``design-review`` and
``design-review-confirm``. Nothing here exists yet, so every test that touches a
new subcommand is expected to be RED until ``argument_parser`` grows them.

The regression half (N35) is green today and must stay green: registering a new
subcommand may not disturb the eight siblings already on the parser.

Discovered from source, not from the plan:

* ``risk.py:182`` ``RiskArgumentError(ValueError)``
* ``risk.py:186`` ``_StrictArgumentParser.error`` raises it instead of exiting
* ``risk.py:191`` ``_StoreOnce`` raises ``argparse.ArgumentError`` on a repeat,
  which argparse converts back into ``parser.error`` — so a repeated flag also
  surfaces as ``RiskArgumentError``
* ``risk.py:3273`` ``_add_path_argument`` — ``type=Path, required=True,
  action=_StoreOnce``
* ``risk.py:3279`` the root parser is built with ``allow_abbrev=False`` and
  every ``add_parser`` call repeats it
* ``risk.py:3642`` ``main`` maps ``RiskArgumentError`` to exit code **2**;
  ``risk.py:3641``/``3631`` map recorded problems to **1** and a clean run to
  **0**
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

import risk


# --- Frozen baseline, read from risk.py:3282-3371 -------------------------

SEVEN_DOCUMENT_PATHS = frozenset(
    {
        "--project-root",
        "--policy",
        "--threats",
        "--assessment",
        "--requirements",
        "--evidence",
        "--state",
    }
)
CONFIRMATION_FLAGS = frozenset({"--by", "--authority"})

# The eight subcommands that exist today, with the exact option set each one
# declares. Frozen so that adding a ninth and a tenth cannot quietly reshape a
# sibling.
BASELINE_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "policy-confirm": frozenset({"--project-root", "--policy"}) | CONFIRMATION_FLAGS,
    "confirm": SEVEN_DOCUMENT_PATHS | CONFIRMATION_FLAGS,
    "check": SEVEN_DOCUMENT_PATHS,
    "evidence": frozenset({"--project-root", "--requirements", "--evidence"}),
    "residual": SEVEN_DOCUMENT_PATHS,
    "residual-confirm": SEVEN_DOCUMENT_PATHS | CONFIRMATION_FLAGS,
    "migrate": frozenset(
        {
            "--project-root",
            "--threats",
            "--requirements",
            "--policy",
            "--assessment",
            "--state",
        }
    ),
    "refresh": SEVEN_DOCUMENT_PATHS,
}

DESIGN_REVIEW = "design-review"
DESIGN_REVIEW_CONFIRM = "design-review-confirm"
NEW_SUBCOMMANDS = (DESIGN_REVIEW, DESIGN_REVIEW_CONFIRM)

MODE_CHOICES = ("guided", "quick")
RISK_APPETITE_CHOICES = ("conservative", "standard", "tolerant")

USAGE_EXIT_CODE = 2


# --- Helpers ---------------------------------------------------------------
#
# argparse exposes no public accessor for a parser's subcommands or actions, and
# the repo has no wrapper, so these read the documented private attributes.


def _subparsers_action(parser: argparse.ArgumentParser) -> argparse._SubParsersAction:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action
    raise AssertionError("risk.argument_parser() declares no subcommands")


def _subcommands() -> dict[str, argparse.ArgumentParser]:
    return dict(_subparsers_action(risk.argument_parser()).choices)


def _require_subcommand(name: str) -> argparse.ArgumentParser:
    """Return the subparser for ``name``, failing loudly when it is missing."""

    registered = _subcommands()
    assert name in registered, (
        f"{name!r} is not registered on risk.argument_parser(); "
        f"registered subcommands are {sorted(registered)}"
    )
    return registered[name]


def _options(parser: argparse.ArgumentParser) -> dict[str, argparse.Action]:
    """Map every long option on ``parser`` to its action, ignoring ``--help``."""

    return {
        option: action
        for action in parser._actions
        for option in action.option_strings
        if option.startswith("--") and option != "--help"
    }


def _sample_value(action: argparse.Action) -> str:
    if action.choices:
        return str(sorted(action.choices)[0])
    return f"placeholder-{action.dest.replace('_', '-')}"


def _minimal_argv(name: str) -> list[str]:
    """Build the shortest argv that satisfies every required option of ``name``."""

    parser = _require_subcommand(name)
    argv = [name]
    for option, action in _options(parser).items():
        if action.required:
            argv.extend([option, _sample_value(action)])
    return argv


def _parse(argv: list[str]) -> argparse.Namespace:
    return risk.argument_parser().parse_args(argv)


# --- N35: both new subcommands register, the eight siblings are untouched ---


def test_the_parser_still_offers_exactly_its_eight_original_subcommands():
    """N35 (regression) — no existing subcommand may be renamed or dropped."""

    registered = set(_subcommands())

    missing = set(BASELINE_SUBCOMMANDS) - registered
    assert not missing, f"existing subcommands disappeared: {sorted(missing)}"

    # Anything added beyond the baseline must be one of the two planned ones.
    unexpected = registered - set(BASELINE_SUBCOMMANDS) - set(NEW_SUBCOMMANDS)
    assert not unexpected, f"unplanned subcommands appeared: {sorted(unexpected)}"


@pytest.mark.parametrize("name", sorted(BASELINE_SUBCOMMANDS))
def test_each_existing_subcommand_still_declares_its_original_flag_set(name):
    """N35 (regression) — flag sets frozen from risk.py:3282-3371."""

    parser = _require_subcommand(name)
    options = _options(parser)

    assert frozenset(options) == BASELINE_SUBCOMMANDS[name]
    for option, action in options.items():
        assert action.required is True, f"{name} {option} stopped being required"
        assert isinstance(action, risk._StoreOnce), (
            f"{name} {option} stopped using _StoreOnce"
        )


@pytest.mark.parametrize("name", sorted(BASELINE_SUBCOMMANDS))
def test_each_existing_subcommand_still_parses_its_current_argv_unchanged(name):
    """N35 (regression) — adding a subcommand may not break its siblings."""

    argv = _minimal_argv(name)
    args = _parse(argv)

    assert args.command == name
    for option in BASELINE_SUBCOMMANDS[name]:
        assert hasattr(args, option.removeprefix("--").replace("-", "_"))


@pytest.mark.parametrize("name", sorted(BASELINE_SUBCOMMANDS))
def test_no_existing_subcommand_absorbs_a_design_review_flag(name):
    """N35 (regression) — the new flags belong to the new subcommands only."""

    options = _options(_require_subcommand(name))
    for leaked in ("--mode", "--risk-appetite", "--scope", "--output", "--profile"):
        assert leaked not in options, f"{name} unexpectedly grew {leaked}"


@pytest.mark.parametrize("name", NEW_SUBCOMMANDS)
def test_the_new_subcommand_registers_on_the_existing_parser(name):
    """N35 — one parser, two more subcommands; not a second script."""

    parser = _require_subcommand(name)

    assert isinstance(parser, risk._StrictArgumentParser), (
        f"{name} must reuse _StrictArgumentParser so usage errors raise "
        "RiskArgumentError instead of calling sys.exit"
    )
    assert parser.allow_abbrev is False, f"{name} must be built allow_abbrev=False"


# --- N33: --profile is gone and the message names its replacement ----------


@pytest.mark.parametrize("name", NEW_SUBCOMMANDS)
def test_supplying_profile_raises_and_the_message_names_risk_appetite(name):
    """N33 — a bare rejection sends the reader to the docs; name the successor."""

    _require_subcommand(name)

    with pytest.raises(risk.RiskArgumentError) as excinfo:
        _parse(_minimal_argv(name) + ["--profile", "core"])

    message = str(excinfo.value)
    assert "--profile" in message
    assert "--risk-appetite" in message, (
        "§2.1 decision 8 replaced --profile with --risk-appetite because "
        f"--profile collided with the service profile.yaml; message was {message!r}"
    )


@pytest.mark.parametrize("name", NEW_SUBCOMMANDS)
def test_supplying_profile_exits_two_through_the_existing_usage_path(name):
    """N33 — §7 constraint 1: --profile supplied → exit 2."""

    _require_subcommand(name)

    assert risk.main(_minimal_argv(name) + ["--profile", "core"]) == USAGE_EXIT_CODE


# --- N34: required path flags and no repeated flags ------------------------


@pytest.mark.parametrize("name", NEW_SUBCOMMANDS)
def test_every_path_flag_on_the_new_subcommand_is_required_and_stores_once(name):
    """N34 — the contract _add_path_argument (risk.py:3273) already encodes."""

    parser = _require_subcommand(name)
    options = _options(parser)

    path_options = {
        option: action for option, action in options.items() if action.type is Path
    }
    assert path_options, f"{name} declares no path flag at all"
    assert "--project-root" in path_options, (
        f"{name} must take --project-root: §7 constraint 21 requires a repository "
        "root to contain --output against"
    )

    for option, action in path_options.items():
        assert action.required is True, f"{name} {option} must be required=True"
        assert isinstance(action, risk._StoreOnce), (
            f"{name} {option} must use _StoreOnce"
        )


@pytest.mark.parametrize("name", NEW_SUBCOMMANDS)
def test_repeating_any_flag_twice_on_the_new_subcommand_is_rejected(name):
    """N34 — _StoreOnce (risk.py:191) applies to every flag, not just paths."""

    parser = _require_subcommand(name)
    baseline = _minimal_argv(name)

    for option, action in _options(parser).items():
        repeated = baseline + [option, _sample_value(action)]
        # `baseline` holds only the *required* flags, so for an optional one the
        # line above is a first occurrence rather than a repeat. Append a second
        # time to make the argv actually say the flag twice, or this test passes
        # vacuously for every optional flag on the subcommand.
        if repeated.count(option) < 2:
            repeated += [option, _sample_value(action)]
        with pytest.raises(risk.RiskArgumentError) as excinfo:
            _parse(repeated)
        assert "only once" in str(excinfo.value), (
            f"{name} {option} was not rejected by _StoreOnce: {excinfo.value}"
        )


@pytest.mark.parametrize("name", NEW_SUBCOMMANDS)
def test_omitting_a_required_flag_on_the_new_subcommand_is_a_usage_error(name):
    """N34 — required=True means the flag cannot be dropped, not defaulted."""

    parser = _require_subcommand(name)
    required = [
        option for option, action in _options(parser).items() if action.required
    ]
    assert required, f"{name} declares no required flag"

    for option in required:
        argv = _minimal_argv(name)
        index = argv.index(option)
        del argv[index : index + 2]
        with pytest.raises(risk.RiskArgumentError):
            _parse(argv)
        assert risk.main(argv) == USAGE_EXIT_CODE


# --- §7 constraint 2: the two enums ---------------------------------------


def test_design_review_accepts_only_quick_and_guided_for_mode():
    """§3 Modes / F4 — interview depth is a closed enum."""

    parser = _require_subcommand(DESIGN_REVIEW)
    options = _options(parser)

    assert "--mode" in options, "design-review must accept --mode (plan §3)"
    assert sorted(options["--mode"].choices) == sorted(MODE_CHOICES)

    for value in MODE_CHOICES:
        argv = _minimal_argv(DESIGN_REVIEW)
        if "--mode" in argv:
            argv[argv.index("--mode") + 1] = value
        else:
            argv += ["--mode", value]
        assert _parse(argv).mode == value

    with pytest.raises(risk.RiskArgumentError):
        _parse(_minimal_argv(DESIGN_REVIEW) + ["--mode", "thorough"])


def test_design_review_accepts_only_the_three_risk_appetites():
    """§7 constraint 2 — appetite outside its enum fails loudly."""

    parser = _require_subcommand(DESIGN_REVIEW)
    options = _options(parser)

    assert "--risk-appetite" in options, (
        "design-review must accept --risk-appetite (plan §3)"
    )
    assert sorted(options["--risk-appetite"].choices) == sorted(RISK_APPETITE_CHOICES)

    for value in RISK_APPETITE_CHOICES:
        argv = _minimal_argv(DESIGN_REVIEW)
        if "--risk-appetite" in argv:
            argv[argv.index("--risk-appetite") + 1] = value
        else:
            argv += ["--risk-appetite", value]
        assert _parse(argv).risk_appetite == value

    with pytest.raises(risk.RiskArgumentError):
        _parse(_minimal_argv(DESIGN_REVIEW) + ["--risk-appetite", "core"])


@pytest.mark.parametrize("name", NEW_SUBCOMMANDS)
def test_an_enum_flag_shared_by_both_subcommands_keeps_the_same_choices(name):
    """§7 constraint 2 — one enum, not one per subcommand."""

    options = _options(_require_subcommand(name))
    expected = {"--mode": MODE_CHOICES, "--risk-appetite": RISK_APPETITE_CHOICES}
    for option, choices in expected.items():
        if option in options:
            assert sorted(options[option].choices) == sorted(choices)


# --- allow_abbrev=False ----------------------------------------------------


@pytest.mark.parametrize("name", NEW_SUBCOMMANDS)
def test_an_abbreviated_flag_is_rejected_rather_than_silently_accepted(name):
    """allow_abbrev=False — a prefix must not resolve to its long form."""

    parser = _require_subcommand(name)
    options = _options(parser)

    abbreviated = {
        option: option[:-1]
        for option in options
        if len(option) > 4 and option[:-1] not in options
    }
    assert abbreviated, f"{name} has no flag long enough to abbreviate"

    for option, prefix in abbreviated.items():
        argv = _minimal_argv(name)
        if option in argv:
            argv[argv.index(option)] = prefix
        else:
            argv += [prefix, _sample_value(options[option])]
        with pytest.raises(risk.RiskArgumentError):
            _parse(argv)


@pytest.mark.parametrize("name", NEW_SUBCOMMANDS)
def test_an_unknown_flag_on_the_new_subcommand_is_a_usage_error(name):
    """F1 — reject unknown flags; the grammar is closed."""

    _require_subcommand(name)

    with pytest.raises(risk.RiskArgumentError):
        _parse(_minimal_argv(name) + ["--publish", "true"])
    assert risk.main(_minimal_argv(name) + ["--publish", "true"]) == USAGE_EXIT_CODE


# --- F21: the preview / authoritative split -------------------------------


def test_design_review_confirm_requires_both_by_and_authority():
    """F21 — authoritative artifacts need a named party and an authority."""

    parser = _require_subcommand(DESIGN_REVIEW_CONFIRM)
    options = _options(parser)

    for option in CONFIRMATION_FLAGS:
        assert option in options, f"design-review-confirm must accept {option}"
        assert options[option].required is True
        assert isinstance(options[option], risk._StoreOnce)

    assert sorted(options["--authority"].choices) == sorted(risk.AUTHORITIES)

    for omitted in CONFIRMATION_FLAGS:
        argv = _minimal_argv(DESIGN_REVIEW_CONFIRM)
        index = argv.index(omitted)
        del argv[index : index + 2]
        with pytest.raises(risk.RiskArgumentError):
            _parse(argv)
        assert risk.main(argv) == USAGE_EXIT_CODE


def test_design_review_is_a_preview_and_takes_no_confirmation_flags():
    """F21 — no single run may both interview and emit authoritative output."""

    options = _options(_require_subcommand(DESIGN_REVIEW))

    for option in CONFIRMATION_FLAGS:
        assert option not in options, (
            f"design-review must not accept {option}; the confirmation gate is "
            "what forces the split into two subcommands (plan §3)"
        )


# --- Exit codes 0 / 1 / 2 --------------------------------------------------


def test_the_usage_path_exits_two_for_every_shape_of_grammar_error():
    """§3 — 0 ok / 1 problems / 2 usage; every usage error lands on 2."""

    _require_subcommand(DESIGN_REVIEW)
    baseline = _minimal_argv(DESIGN_REVIEW)
    duplicated = baseline + ["--project-root", "elsewhere"]

    for argv in (
        baseline + ["--profile", "core"],
        baseline + ["--mode", "thorough"],
        baseline + ["--risk-appetite", "core"],
        duplicated,
        ["design-revie"],
    ):
        assert risk.main(argv) == USAGE_EXIT_CODE, f"{argv} did not exit 2"


def test_the_usage_exit_code_comes_from_the_existing_risk_argument_error_path():
    """§3 — the new subcommands reuse main's handler, they do not add one."""

    # risk.py:3642 is the only place that maps a grammar failure to 2, and it is
    # reached because _StrictArgumentParser.error raises instead of exiting.
    with pytest.raises(risk.RiskArgumentError):
        _parse(["design-revie"])
    assert risk.main(["design-revie"]) == USAGE_EXIT_CODE
    assert issubclass(risk.RiskArgumentError, ValueError)
