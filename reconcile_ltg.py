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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Preserve current LTG mappings for existing licenses and keep source "
            "CSV mappings only for new or currently unmapped licenses."
        )
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
        default=Path("license_threat_groups_02272026.csv"),
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


def load_licenses(path: Path) -> set[str]:
    _, rows = load_json_list(path, LICENSE_TOP_LEVEL_KEYS)
    missing_ids = [index + 1 for index, row in enumerate(rows) if not row.get("id")]
    if missing_ids:
        fail(f"{path} has license entries without an 'id' field: {missing_ids[:10]}")
    return {row["id"].strip() for row in rows}


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
    csv_duplicates: list[dict[str, object]],
    multi_assignments: list[dict[str, object]],
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
            "licensesWithMultipleCurrentIQThreatGroups": len(multi_assignments),
            "licensesMissingFromLicenseExport": len(missing_from_license_export),
        },
        "missingThreatGroups": missing_groups,
        "unresolvedExistingMappings": unresolved_existing_mappings,
        "changedMappings": changed_mappings,
        "addedLicenses": added_licenses,
        "csvDuplicates": csv_duplicates,
        "multipleCurrentIQThreatGroupAssignments": multi_assignments,
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
    source_csv_path = args.input_csv.resolve()
    output_csv_path = args.output_csv.resolve()
    report_json_path = args.report_json.resolve()
    unresolved_csv_path = args.unresolved_csv.resolve()
    changed_mappings_csv_path = args.changed_mappings_csv.resolve()
    added_licenses_csv_path = args.added_licenses_csv.resolve()

    known_licenses = load_licenses(licenses_path)
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
    missing_from_license_export: list[str] = []
    preserved_existing_rows = 0
    kept_source_rows = 0
    changed_from_source_rows = 0

    for entry in source_entries:
        if entry.license_id not in known_licenses:
            missing_from_license_export.append(entry.license_id)

        existing_group_ids = current_assignments.get(entry.license_id, [])
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
                        "licenseId": entry.license_id,
                        "currentThreatGroupId": None,
                        "currentThreatGroupIds": existing_group_ids,
                        "currentThreatGroupNames": current_group_names,
                        "sourceThreatGroup": entry.source_group,
                        "reason": "One or more current IQ mappings point to threat-group IDs with no known name.",
                    }
                )
                continue

            for group_name in current_group_names:
                output_rows.append((entry.license_id, group_name))
            preserved_existing_rows += len(current_group_names)

            if len(current_group_names) != 1 or current_group_names[0] != entry.source_group:
                changed_from_source_rows += 1
                changed_mappings.append(
                    {
                        "licenseId": entry.license_id,
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
            missing_groups[entry.source_group].append(entry.license_id)
            continue

        output_rows.append((entry.license_id, entry.source_group))
        kept_source_rows += 1
        added_licenses.append(
            {
                "licenseId": entry.license_id,
                "targetThreatGroup": entry.source_group,
                "status": (
                    "new_to_license_export"
                    if entry.license_id not in known_licenses
                    else "existing_license_unmapped"
                ),
                "reason": (
                    "Added from the source CSV because the license was not present "
                    "in the IQ license export."
                    if entry.license_id not in known_licenses
                    else "Added from the source CSV because the license has no current IQ LTG assignment."
                ),
            }
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
        csv_duplicates=csv_duplicates,
        multi_assignments=multi_assignments,
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
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
