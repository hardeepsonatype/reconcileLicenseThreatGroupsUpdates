#!/usr/bin/env python3
"""Reconcile an LTG updater CSV against current IQ Server exports.

The script preserves the current mapping for licenses already assigned to a
license threat group in IQ Server. For licenses that are new or currently
unmapped, it keeps the mapping from the source CSV if that threat group exists.

Preferred inputs:
  - license.json
  - licenseThreatGroupLicense.json
  - licenseThreatGroup.json (optional but recommended)
  - source CSV without a header: license_name,license_threat_group_name

If the threat-group definition export is unavailable, the script can infer
group names from the source CSV with --infer-group-names. That mode is
best-effort and writes clear warnings to the report.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


LICENSE_TOP_LEVEL_KEYS = ("license",)
ASSIGNMENT_TOP_LEVEL_KEYS = ("licenseThreatGroupLicense",)
THREAT_GROUP_TOP_LEVEL_KEYS = ("licenseThreatGroup", "licenseThreatGroups")
THREAT_GROUP_NAME_KEYS = (
    "name",
    "displayName",
    "shortDisplayName",
    "longDisplayName",
    "label",
)
APP_VERSION = "1.1.0"


@dataclass(frozen=True)
class CsvEntry:
    license_id: str
    source_group: str
    row_number: int


@dataclass(frozen=True)
class GroupInference:
    name: str
    exact: bool
    confidence: float
    evidence_count: int
    alternatives: tuple[tuple[str, int], ...]
    note: str


@dataclass(frozen=True)
class LicenseCatalog:
    known_ids: frozenset[str]
    ids_by_short_name: dict[str, tuple[str, ...]]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Preserve current LTG mappings for existing licenses and keep source "
            "CSV mappings only for new or currently unmapped licenses."
        )
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {APP_VERSION}",
    )
    parser.add_argument(
        "source_csv",
        nargs="?",
        type=Path,
        help="Path to the source LTG updater CSV.",
    )
    parser.add_argument(
        "--licenses",
        type=Path,
        default=Path("license.json"),
        help="Path to the IQ Server license export JSON.",
    )
    parser.add_argument(
        "--assignments",
        type=Path,
        default=Path("licenseThreatGroupLicense.json"),
        help="Path to the IQ Server licenseThreatGroupLicense export JSON.",
    )
    parser.add_argument(
        "--threat-groups",
        type=Path,
        default=None,
        help=(
            "Path to the IQ Server licenseThreatGroup export JSON. If omitted, "
            "the script will auto-detect a JSON export with threat-group data."
        ),
    )
    parser.add_argument(
        "--input-csv",
        type=Path,
        default=None,
        help="Path to the source LTG updater CSV.",
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=Path("license_threat_groups_reconciled.csv"),
        help="Path for the reconciled CSV output.",
    )
    parser.add_argument(
        "--report-json",
        type=Path,
        default=Path("license_threat_groups_reconciled_report.json"),
        help="Path for the reconciliation report JSON.",
    )
    parser.add_argument(
        "--unresolved-csv",
        type=Path,
        default=Path("license_threat_groups_unresolved.csv"),
        help=(
            "Path for a CSV listing licenses that could not be reconciled safely, "
            "including multiple current LTG assignments."
        ),
    )
    parser.add_argument(
        "--changed-mappings-csv",
        type=Path,
        default=Path("license_threat_groups_changed_mappings.csv"),
        help=(
            "Path for a CSV listing licenses where the source CSV mapping differs "
            "from the current IQ mapping that was preserved."
        ),
    )
    parser.add_argument(
        "--added-licenses-csv",
        type=Path,
        default=Path("license_threat_groups_added_licenses.csv"),
        help=(
            "Path for a CSV listing licenses added from the source CSV because "
            "they were new to IQ or currently unmapped."
        ),
    )
    parser.add_argument(
        "--resolved-license-aliases-csv",
        type=Path,
        default=Path("license_threat_groups_resolved_license_aliases.csv"),
        help=(
            "Path for a CSV listing source license IDs that were resolved to a "
            "different IQ license ID during reconciliation."
        ),
    )
    parser.add_argument(
        "--multiple-groups-csv",
        type=Path,
        default=Path("license_threat_groups_multiple_groups_report.csv"),
        help=(
            "Path for a CSV comparing licenses that belong to more than one "
            "threat group in the current IQ data and/or the reconciled output."
        ),
    )
    parser.add_argument(
        "--infer-group-names",
        action="store_true",
        help=(
            "Infer threat-group names from the source CSV when a "
            "licenseThreatGroup export is unavailable."
        ),
    )
    parser.add_argument(
        "--allow-header",
        action="store_true",
        help="Skip the first CSV row if it looks like a header.",
    )
    return parser.parse_args()


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json_list(path: Path, top_level_keys: Iterable[str]) -> tuple[str, list[dict]]:
    try:
        payload = json.loads(path.read_text())
    except FileNotFoundError:
        fail(f"Missing required file: {path}")
    except json.JSONDecodeError as exc:
        fail(f"Could not parse JSON in {path}: {exc}")

    if not isinstance(payload, dict):
        fail(f"{path} must contain a top-level JSON object.")

    for key in top_level_keys:
        value = payload.get(key)
        if isinstance(value, list):
            if not all(isinstance(item, dict) for item in value):
                fail(f"{path} contains non-object entries under '{key}'.")
            return key, value

    expected = ", ".join(top_level_keys)
    fail(f"{path} did not contain any of the expected top-level keys: {expected}")
    raise AssertionError("unreachable")


def try_load_json_list(path: Path, top_level_keys: Iterable[str]) -> tuple[str, list[dict]] | None:
    try:
        payload = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None

    if not isinstance(payload, dict):
        return None

    for key in top_level_keys:
        value = payload.get(key)
        if isinstance(value, list) and all(isinstance(item, dict) for item in value):
            return key, value

    return None


def auto_detect_threat_group_export(base_dir: Path, exclude: set[Path]) -> Path | None:
    exclude = {path.resolve() for path in exclude}
    for candidate in sorted(base_dir.glob("*.json")):
        if candidate.resolve() in exclude:
            continue
        loaded = try_load_json_list(candidate, THREAT_GROUP_TOP_LEVEL_KEYS)
        if loaded is None:
            continue
        _, rows = loaded
        if rows:
            return candidate
    return None


def auto_detect_source_csv(base_dir: Path) -> Path | None:
    excluded_names = {
        "license_threat_groups_reconciled.csv",
        "license_threat_groups_unresolved.csv",
        "license_threat_groups_changed_mappings.csv",
        "license_threat_groups_added_licenses.csv",
        "license_threat_groups_resolved_license_aliases.csv",
        "license_threat_groups_multiple_groups_report.csv",
    }
    candidates = [
        path
        for path in sorted(base_dir.glob("license_threat_groups*.csv"))
        if path.name not in excluded_names
    ]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        return None
    fail(
        "Multiple possible source CSV files were found. Please specify one with "
        "'--input-csv <file>' or as the first positional argument."
    )
    raise AssertionError("unreachable")


def resolve_source_csv(args: argparse.Namespace, base_dir: Path) -> Path:
    provided_paths = [path for path in (args.source_csv, args.input_csv) if path is not None]
    if len(provided_paths) == 2 and provided_paths[0].resolve() != provided_paths[1].resolve():
        fail("Provide the source CSV only once, either positionally or with --input-csv.")
    if provided_paths:
        return provided_paths[0].resolve()

    detected = auto_detect_source_csv(base_dir)
    if detected is not None:
        return detected.resolve()

    fail(
        "Could not find a source LTG CSV automatically. Please specify it with "
        "'--input-csv <file>' or as the first positional argument."
    )
    raise AssertionError("unreachable")


def load_license_catalog(path: Path) -> LicenseCatalog:
    _, rows = load_json_list(path, LICENSE_TOP_LEVEL_KEYS)
    missing_ids = [index + 1 for index, row in enumerate(rows) if not row.get("id")]
    if missing_ids:
        fail(f"{path} has license entries without an 'id' field: {missing_ids[:10]}")
    known_ids: set[str] = set()
    ids_by_short_name_sets: dict[str, set[str]] = defaultdict(set)

    for row in rows:
        license_id = row["id"].strip()
        known_ids.add(license_id)

        short_name = str(row.get("shortDisplayName", "")).strip()
        if short_name:
            ids_by_short_name_sets[short_name].add(license_id)

    return LicenseCatalog(
        known_ids=frozenset(known_ids),
        ids_by_short_name={
            short_name: tuple(sorted(ids))
            for short_name, ids in ids_by_short_name_sets.items()
        },
    )


def load_assignments(
    path: Path,
) -> tuple[dict[str, list[str]], list[dict[str, object]]]:
    _, rows = load_json_list(path, ASSIGNMENT_TOP_LEVEL_KEYS)
    groups_by_license: dict[str, set[str]] = defaultdict(set)

    for row in rows:
        license_id = str(row.get("licenseId", "")).strip()
        group_id = str(row.get("licenseThreatGroupId", "")).strip()
        if not license_id or not group_id:
            continue
        groups_by_license[license_id].add(group_id)

    assignments_by_license: dict[str, list[str]] = {}
    multi_assignments: list[dict[str, object]] = []
    for license_id, group_ids in groups_by_license.items():
        sorted_group_ids = sorted(group_ids)
        assignments_by_license[license_id] = sorted_group_ids
        if len(group_ids) > 1:
            multi_assignments.append(
                {
                    "licenseId": license_id,
                    "groupIds": sorted_group_ids,
                }
            )

    return assignments_by_license, multi_assignments


def normalize_csv_entry(row: list[str], row_number: int, allow_header: bool) -> CsvEntry | None:
    if not row or all(not cell.strip() for cell in row):
        return None

    if len(row) < 2:
        fail(f"CSV row {row_number} does not have at least 2 columns: {row}")

    license_id = row[0].strip()
    group_name = row[1].strip()

    if row_number == 1 and allow_header:
        header_tokens = {license_id.lower(), group_name.lower()}
        if header_tokens & {"license", "license name", "license id"} and (
            "group" in group_name.lower() or "threat" in group_name.lower()
        ):
            return None

    if not license_id or not group_name:
        fail(f"CSV row {row_number} must contain both a license and a threat group.")

    return CsvEntry(license_id=license_id, source_group=group_name, row_number=row_number)


def load_source_csv(path: Path, allow_header: bool) -> tuple[list[CsvEntry], list[dict[str, object]]]:
    try:
        handle = path.open(newline="")
    except FileNotFoundError:
        fail(f"Missing required file: {path}")

    entries: list[CsvEntry] = []
    duplicates: list[dict[str, object]] = []
    seen: dict[str, CsvEntry] = {}

    with handle:
        reader = csv.reader(handle)
        for row_number, row in enumerate(reader, start=1):
            entry = normalize_csv_entry(row, row_number=row_number, allow_header=allow_header)
            if entry is None:
                continue

            previous = seen.get(entry.license_id)
            if previous:
                duplicates.append(
                    {
                        "licenseId": entry.license_id,
                        "firstRow": previous.row_number,
                        "duplicateRow": entry.row_number,
                        "firstGroup": previous.source_group,
                        "duplicateGroup": entry.source_group,
                    }
                )
                continue

            seen[entry.license_id] = entry
            entries.append(entry)

    return entries, duplicates


def load_exact_threat_groups(path: Path) -> dict[str, GroupInference]:
    _, rows = load_json_list(path, THREAT_GROUP_TOP_LEVEL_KEYS)
    mapping: dict[str, GroupInference] = {}

    for row in rows:
        group_id = str(row.get("id", "")).strip()
        group_name = ""
        for key in THREAT_GROUP_NAME_KEYS:
            value = row.get(key)
            if isinstance(value, str) and value.strip():
                group_name = value.strip()
                break
        if not group_id or not group_name:
            continue

        mapping[group_id] = GroupInference(
            name=group_name,
            exact=True,
            confidence=1.0,
            evidence_count=0,
            alternatives=(),
            note="Loaded from threat-group export.",
        )

    if not mapping:
        fail(
            f"{path} did not contain any threat-group entries with both an id and a name."
        )

    return mapping


def infer_threat_groups(
    assignments: dict[str, str],
    source_entries: list[CsvEntry],
) -> dict[str, GroupInference]:
    csv_by_license = {entry.license_id: entry.source_group for entry in source_entries}
    votes_by_group_id: dict[str, Counter[str]] = defaultdict(Counter)

    for license_id, group_id in assignments.items():
        source_group = csv_by_license.get(license_id)
        if source_group:
            votes_by_group_id[group_id][source_group] += 1

    inferred: dict[str, GroupInference] = {}

    for group_id, counter in votes_by_group_id.items():
        if not counter:
            continue

        most_common = counter.most_common()
        top_name, top_count = most_common[0]
        total = sum(counter.values())
        confidence = top_count / total if total else 0.0

        exact = len(counter) == 1
        note = "Inferred cleanly from source CSV."
        if not exact:
            note = "Inferred from source CSV with conflicting evidence."

        inferred[group_id] = GroupInference(
            name=top_name,
            exact=exact,
            confidence=confidence,
            evidence_count=total,
            alternatives=tuple(most_common),
            note=note,
        )

    return inferred


def build_unspecified_alias_candidates(
    source_license_id: str,
    license_catalog: LicenseCatalog,
) -> list[tuple[str, str]]:
    if not source_license_id.endswith("-UNSPECIFIED"):
        return []

    stem = source_license_id[: -len("-UNSPECIFIED")]
    candidates: list[tuple[str, str]] = []
    if stem in license_catalog.known_ids:
        candidates.append((stem, "stripped_unspecified_suffix"))

    for license_id in license_catalog.ids_by_short_name.get(stem, ()):
        candidates.append((license_id, "matched_short_display_name"))

    deduplicated: list[tuple[str, str]] = []
    seen_ids: set[str] = set()
    for candidate_id, resolution_type in candidates:
        if candidate_id == source_license_id or candidate_id in seen_ids:
            continue
        seen_ids.add(candidate_id)
        deduplicated.append((candidate_id, resolution_type))

    return deduplicated


def resolve_source_license_id(
    *,
    source_license_id: str,
    license_catalog: LicenseCatalog,
    current_assignments: dict[str, list[str]],
) -> tuple[str, dict[str, object] | None]:
    exact_known = source_license_id in license_catalog.known_ids
    exact_has_assignments = bool(current_assignments.get(source_license_id))

    if exact_has_assignments:
        return source_license_id, None

    candidates = build_unspecified_alias_candidates(source_license_id, license_catalog)
    candidates_with_assignments = [
        (candidate_id, resolution_type)
        for candidate_id, resolution_type in candidates
        if current_assignments.get(candidate_id)
    ]

    if len(candidates_with_assignments) == 1:
        resolved_id, resolution_type = candidates_with_assignments[0]
        reason = (
            "Used a unique alias because the source license ID did not carry the "
            "current IQ threat-group assignment."
        )
        return resolved_id, {
            "sourceLicenseId": source_license_id,
            "resolvedLicenseId": resolved_id,
            "resolutionType": resolution_type,
            "reason": reason,
        }

    if exact_known:
        return source_license_id, None

    if len(candidates) == 1:
        resolved_id, resolution_type = candidates[0]
        reason = (
            "Used a unique alias because the source license ID was not present in "
            "the IQ license export."
        )
        return resolved_id, {
            "sourceLicenseId": source_license_id,
            "resolvedLicenseId": resolved_id,
            "resolutionType": resolution_type,
            "reason": reason,
        }

    return source_license_id, None


def group_output_rows_by_license(rows: Iterable[tuple[str, str]]) -> dict[str, list[str]]:
    groups_by_license: dict[str, set[str]] = defaultdict(set)

    for license_id, group_name in rows:
        normalized_license_id = str(license_id).strip()
        normalized_group_name = str(group_name).strip()
        if not normalized_license_id or not normalized_group_name:
            continue
        groups_by_license[normalized_license_id].add(normalized_group_name)

    return {
        license_id: sorted(group_names)
        for license_id, group_names in groups_by_license.items()
    }


def build_multiple_group_comparisons(
    *,
    current_assignments: dict[str, list[str]],
    reconciled_groups_by_license: dict[str, list[str]],
    source_entries: list[CsvEntry],
    group_by_id: dict[str, GroupInference],
) -> tuple[list[dict[str, object]], int]:
    relevant_license_ids = {entry.license_id for entry in source_entries}
    source_group_by_license = {
        entry.license_id: entry.source_group for entry in source_entries
    }
    multiple_reconciled_count = sum(
        1 for group_names in reconciled_groups_by_license.values() if len(group_names) > 1
    )
    licenses_to_report = sorted(
        license_id
        for license_id in relevant_license_ids
        if len(current_assignments.get(license_id, [])) > 1
        or len(reconciled_groups_by_license.get(license_id, [])) > 1
    )

    comparisons: list[dict[str, object]] = []
    for license_id in licenses_to_report:
        current_group_ids = current_assignments.get(license_id, [])
        current_group_names = [
            group_by_id[group_id].name
            for group_id in current_group_ids
            if group_id in group_by_id
        ]
        reconciled_group_names = reconciled_groups_by_license.get(license_id, [])
        has_multiple_current = len(current_group_ids) > 1
        has_multiple_reconciled = len(reconciled_group_names) > 1

        if has_multiple_current and has_multiple_reconciled:
            reason = (
                "License has multiple current IQ threat groups, and reconciliation "
                "preserved multiple threat-group rows."
            )
        elif has_multiple_current:
            reason = (
                "License has multiple current IQ threat groups, but the "
                "reconciled output does not contain multiple threat-group rows."
            )
        else:
            reason = (
                "License does not have multiple current IQ threat groups, but "
                "the reconciled output contains multiple threat-group rows."
            )

        comparisons.append(
            {
                "licenseId": license_id,
                "sourceThreatGroup": source_group_by_license.get(license_id),
                "currentThreatGroupIds": current_group_ids,
                "currentThreatGroupNames": current_group_names,
                "reconciledThreatGroupNames": reconciled_group_names,
                "hasMultipleCurrentThreatGroups": has_multiple_current,
                "hasMultipleReconciledThreatGroups": has_multiple_reconciled,
                "reason": reason,
            }
        )

    return comparisons, multiple_reconciled_count


def build_report(
    *,
    licenses_path: Path,
    assignments_path: Path,
    threat_groups_path: Path | None,
    source_csv_path: Path,
    output_csv_path: Path,
    report_json_path: Path,
    unresolved_csv_path: Path,
    changed_mappings_csv_path: Path,
    added_licenses_csv_path: Path,
    resolved_license_aliases_csv_path: Path,
    multiple_groups_csv_path: Path,
    mode: str,
    total_input_rows: int,
    written_rows: int,
    preserved_existing_rows: int,
    kept_source_rows: int,
    changed_from_source_rows: int,
    missing_groups: dict[str, list[str]],
    unresolved_existing_mappings: list[dict[str, object]],
    changed_mappings: list[dict[str, object]],
    added_licenses: list[dict[str, object]],
    resolved_license_aliases: list[dict[str, object]],
    csv_duplicates: list[dict[str, object]],
    multi_assignments: list[dict[str, object]],
    multiple_group_comparisons: list[dict[str, object]],
    multiple_reconciled_count: int,
    missing_from_license_export: list[str],
    inferred_groups: dict[str, GroupInference],
) -> dict[str, object]:
    report = {
        "inputs": {
            "licenses": str(licenses_path),
            "assignments": str(assignments_path),
            "threatGroups": str(threat_groups_path) if threat_groups_path else None,
            "sourceCsv": str(source_csv_path),
        },
        "outputs": {
            "reconciledCsv": str(output_csv_path),
            "reportJson": str(report_json_path),
            "unresolvedCsv": str(unresolved_csv_path),
            "changedMappingsCsv": str(changed_mappings_csv_path),
            "addedLicensesCsv": str(added_licenses_csv_path),
            "resolvedLicenseAliasesCsv": str(resolved_license_aliases_csv_path),
            "multipleGroupsCsv": str(multiple_groups_csv_path),
        },
        "mode": mode,
        "summary": {
            "totalInputRows": total_input_rows,
            "writtenRows": written_rows,
            "preservedExistingRows": preserved_existing_rows,
            "keptSourceRowsForNewOrUnmappedLicenses": kept_source_rows,
            "rowsChangedFromSourceToMatchCurrentIQMapping": changed_from_source_rows,
            "rowsSkippedBecauseThreatGroupWasMissing": sum(
                len(licenses) for licenses in missing_groups.values()
            ),
            "rowsSkippedBecauseExistingMappingCouldNotBeResolved": len(
                unresolved_existing_mappings
            ),
            "csvDuplicateRowsIgnored": len(csv_duplicates),
            "sourceLicenseIdsResolvedToDifferentIQLicenseId": len(
                resolved_license_aliases
            ),
            "licensesWithMultipleCurrentIQThreatGroups": len(multi_assignments),
            "licensesWithMultipleReconciledThreatGroups": multiple_reconciled_count,
            "licensesInMultipleGroupsComparisonReport": len(multiple_group_comparisons),
            "licensesMissingFromLicenseExport": len(missing_from_license_export),
        },
        "missingThreatGroups": missing_groups,
        "unresolvedExistingMappings": unresolved_existing_mappings,
        "changedMappings": changed_mappings,
        "addedLicenses": added_licenses,
        "resolvedLicenseAliases": resolved_license_aliases,
        "csvDuplicates": csv_duplicates,
        "multipleCurrentIQThreatGroupAssignments": multi_assignments,
        "multipleThreatGroupComparisons": multiple_group_comparisons,
        "licensesMissingFromLicenseExport": missing_from_license_export,
    }

    if inferred_groups:
        report["inferredThreatGroups"] = {
            group_id: {
                "name": info.name,
                "exact": info.exact,
                "confidence": round(info.confidence, 4),
                "evidenceCount": info.evidence_count,
                "alternatives": list(info.alternatives),
                "note": info.note,
            }
            for group_id, info in sorted(inferred_groups.items())
        }

    return report


def main() -> None:
    args = parse_args()

    licenses_path = args.licenses.resolve()
    assignments_path = args.assignments.resolve()
    source_csv_path = resolve_source_csv(args, licenses_path.parent)
    output_csv_path = args.output_csv.resolve()
    report_json_path = args.report_json.resolve()
    unresolved_csv_path = args.unresolved_csv.resolve()
    changed_mappings_csv_path = args.changed_mappings_csv.resolve()
    added_licenses_csv_path = args.added_licenses_csv.resolve()
    resolved_license_aliases_csv_path = args.resolved_license_aliases_csv.resolve()
    multiple_groups_csv_path = args.multiple_groups_csv.resolve()

    license_catalog = load_license_catalog(licenses_path)
    current_assignments, multi_assignments = load_assignments(assignments_path)
    source_entries, csv_duplicates = load_source_csv(source_csv_path, allow_header=args.allow_header)

    detected_threat_groups_path = args.threat_groups
    if detected_threat_groups_path is None:
        detected_threat_groups_path = auto_detect_threat_group_export(
            base_dir=licenses_path.parent,
            exclude={licenses_path, assignments_path},
        )

    group_by_id: dict[str, GroupInference] = {}
    mode = "exact"

    if detected_threat_groups_path:
        group_by_id = load_exact_threat_groups(detected_threat_groups_path.resolve())
        mode = "exact"
    elif args.infer_group_names:
        group_by_id = infer_threat_groups(current_assignments, source_entries)
        if not group_by_id:
            fail(
                "Threat-group export was not found and the script could not infer any "
                "threat-group names from the source CSV."
            )
        mode = "inferred"
    else:
        fail(
            "Threat-group export not found. Provide --threat-groups path/to/licenseThreatGroup.json "
            "or rerun with --infer-group-names for a best-effort fallback."
        )

    available_group_names = {info.name for info in group_by_id.values()}
    output_rows: list[tuple[str, str]] = []
    missing_groups: dict[str, list[str]] = defaultdict(list)
    unresolved_existing_mappings: list[dict[str, object]] = []
    changed_mappings: list[dict[str, object]] = []
    added_licenses: list[dict[str, object]] = []
    resolved_license_aliases: list[dict[str, object]] = []
    missing_from_license_export: list[str] = []
    preserved_existing_rows = 0
    kept_source_rows = 0
    changed_from_source_rows = 0

    for entry in source_entries:
        resolved_license_id, alias_resolution = resolve_source_license_id(
            source_license_id=entry.license_id,
            license_catalog=license_catalog,
            current_assignments=current_assignments,
        )
        if alias_resolution is not None:
            resolved_license_aliases.append(alias_resolution)

        if resolved_license_id not in license_catalog.known_ids:
            missing_from_license_export.append(entry.license_id)

        existing_group_ids = current_assignments.get(resolved_license_id, [])
        if existing_group_ids:
            missing_group_ids = [
                group_id for group_id in existing_group_ids if group_id not in group_by_id
            ]
            current_group_names = [
                group_by_id[group_id].name
                for group_id in existing_group_ids
                if group_id in group_by_id
            ]

            if missing_group_ids:
                unresolved_existing_mappings.append(
                    {
                        "licenseId": resolved_license_id,
                        "currentThreatGroupId": None,
                        "currentThreatGroupIds": existing_group_ids,
                        "currentThreatGroupNames": current_group_names,
                        "sourceThreatGroup": entry.source_group,
                        "reason": "One or more current IQ mappings point to threat-group IDs with no known name.",
                    }
                )
                continue

            for group_name in current_group_names:
                output_rows.append((resolved_license_id, group_name))
            preserved_existing_rows += len(current_group_names)

            if len(current_group_names) != 1 or current_group_names[0] != entry.source_group:
                changed_from_source_rows += 1
                changed_mappings.append(
                    {
                        "licenseId": resolved_license_id,
                        "sourceThreatGroup": entry.source_group,
                        "currentThreatGroupIds": existing_group_ids,
                        "currentThreatGroupNames": current_group_names,
                        "reason": (
                            "Preserved all current IQ mappings for this license, including multiple threat groups."
                            if len(current_group_names) > 1
                            else "Preserved the current IQ mapping instead of the source CSV mapping."
                        ),
                    }
                )
            continue

        if entry.source_group not in available_group_names:
            missing_groups[entry.source_group].append(resolved_license_id)
            continue

        output_rows.append((resolved_license_id, entry.source_group))
        kept_source_rows += 1
        added_licenses.append(
            {
                "licenseId": resolved_license_id,
                "targetThreatGroup": entry.source_group,
                "status": (
                    "new_to_license_export"
                    if resolved_license_id not in license_catalog.known_ids
                    else "existing_license_unmapped"
                ),
                "reason": (
                    "Added from the source CSV because the license was not present "
                    "in the IQ license export."
                    if resolved_license_id not in license_catalog.known_ids
                    else "Added from the source CSV because the license has no current IQ LTG assignment."
                ),
            }
        )

    reconciled_groups_by_license = group_output_rows_by_license(output_rows)
    multiple_group_comparisons, multiple_reconciled_count = build_multiple_group_comparisons(
        current_assignments=current_assignments,
        reconciled_groups_by_license=reconciled_groups_by_license,
        source_entries=source_entries,
        group_by_id=group_by_id,
    )

    output_csv_path.parent.mkdir(parents=True, exist_ok=True)
    with output_csv_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerows(output_rows)

    unresolved_csv_path.parent.mkdir(parents=True, exist_ok=True)
    with unresolved_csv_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "licenseId",
                "sourceThreatGroup",
                "currentThreatGroupIds",
                "currentThreatGroupNames",
                "reason",
            ]
        )
        for row in unresolved_existing_mappings:
            writer.writerow(
                [
                    row["licenseId"],
                    row["sourceThreatGroup"],
                    "|".join(row.get("currentThreatGroupIds", [])),
                    "|".join(row.get("currentThreatGroupNames", [])),
                    row["reason"],
                ]
            )

        changed_mappings_csv_path.parent.mkdir(parents=True, exist_ok=True)
    with changed_mappings_csv_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "licenseId",
                "sourceThreatGroup",
                "currentThreatGroupIds",
                "currentThreatGroupNames",
                "reason",
            ]
        )
        for row in changed_mappings:
            writer.writerow(
                [
                    row["licenseId"],
                    row["sourceThreatGroup"],
                    "|".join(row["currentThreatGroupIds"]),
                    "|".join(row["currentThreatGroupNames"]),
                    row["reason"],
                ]
            )

    added_licenses_csv_path.parent.mkdir(parents=True, exist_ok=True)
    with added_licenses_csv_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "licenseId",
                "targetThreatGroup",
                "status",
                "reason",
            ]
        )
        for row in added_licenses:
            writer.writerow(
                [
                    row["licenseId"],
                    row["targetThreatGroup"],
                    row["status"],
                    row["reason"],
                ]
            )

    resolved_license_aliases_csv_path.parent.mkdir(parents=True, exist_ok=True)
    with resolved_license_aliases_csv_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "sourceLicenseId",
                "resolvedLicenseId",
                "resolutionType",
                "reason",
            ]
        )
        for row in resolved_license_aliases:
            writer.writerow(
                [
                    row["sourceLicenseId"],
                    row["resolvedLicenseId"],
                    row["resolutionType"],
                    row["reason"],
                ]
            )

    multiple_groups_csv_path.parent.mkdir(parents=True, exist_ok=True)
    with multiple_groups_csv_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "licenseId",
                "sourceThreatGroup",
                "currentThreatGroupIds",
                "currentThreatGroupNames",
                "reconciledThreatGroupNames",
                "hasMultipleCurrentThreatGroups",
                "hasMultipleReconciledThreatGroups",
                "reason",
            ]
        )
        for row in multiple_group_comparisons:
            writer.writerow(
                [
                    row["licenseId"],
                    row.get("sourceThreatGroup") or "",
                    "|".join(row["currentThreatGroupIds"]),
                    "|".join(row["currentThreatGroupNames"]),
                    "|".join(row["reconciledThreatGroupNames"]),
                    str(row["hasMultipleCurrentThreatGroups"]).lower(),
                    str(row["hasMultipleReconciledThreatGroups"]).lower(),
                    row["reason"],
                ]
            )

    report = build_report(
        licenses_path=licenses_path,
        assignments_path=assignments_path,
        threat_groups_path=detected_threat_groups_path.resolve()
        if detected_threat_groups_path
        else None,
        source_csv_path=source_csv_path,
        output_csv_path=output_csv_path,
        report_json_path=report_json_path,
        unresolved_csv_path=unresolved_csv_path,
        changed_mappings_csv_path=changed_mappings_csv_path,
        added_licenses_csv_path=added_licenses_csv_path,
        resolved_license_aliases_csv_path=resolved_license_aliases_csv_path,
        multiple_groups_csv_path=multiple_groups_csv_path,
        mode=mode,
        total_input_rows=len(source_entries),
        written_rows=len(output_rows),
        preserved_existing_rows=preserved_existing_rows,
        kept_source_rows=kept_source_rows,
        changed_from_source_rows=changed_from_source_rows,
        missing_groups={key: sorted(value) for key, value in sorted(missing_groups.items())},
        unresolved_existing_mappings=unresolved_existing_mappings,
        changed_mappings=changed_mappings,
        added_licenses=added_licenses,
        resolved_license_aliases=resolved_license_aliases,
        csv_duplicates=csv_duplicates,
        multi_assignments=multi_assignments,
        multiple_group_comparisons=multiple_group_comparisons,
        multiple_reconciled_count=multiple_reconciled_count,
        missing_from_license_export=sorted(set(missing_from_license_export)),
        inferred_groups=group_by_id if mode == "inferred" else {},
    )

    report_json_path.parent.mkdir(parents=True, exist_ok=True)
    report_json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    print(
        json.dumps(
            {
                "mode": mode,
                "totalInputRows": len(source_entries),
                "writtenRows": len(output_rows),
                "preservedExistingRows": preserved_existing_rows,
                "keptSourceRowsForNewOrUnmappedLicenses": kept_source_rows,
                "rowsChangedFromSourceToMatchCurrentIQMapping": changed_from_source_rows,
                "rowsSkippedBecauseThreatGroupWasMissing": sum(
                    len(licenses) for licenses in missing_groups.values()
                ),
                "rowsSkippedBecauseExistingMappingCouldNotBeResolved": len(
                    unresolved_existing_mappings
                ),
                "reportJson": str(report_json_path),
                "reconciledCsv": str(output_csv_path),
                "unresolvedCsv": str(unresolved_csv_path),
                "changedMappingsCsv": str(changed_mappings_csv_path),
                "addedLicensesCsv": str(added_licenses_csv_path),
                "resolvedLicenseAliasesCsv": str(resolved_license_aliases_csv_path),
                "multipleGroupsCsv": str(multiple_groups_csv_path),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
