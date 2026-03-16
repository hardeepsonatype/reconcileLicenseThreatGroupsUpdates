License Threat Group Reconciler
================================

Purpose
-------
This application reconciles a Sonatype IQ Server license threat group CSV
against the current state of licenses and threat group assignments exported
from IQ Server.

It is designed to prevent the LTG updater import from overwriting existing IQ
Server mappings when the incoming CSV maps a license differently.

Behavior
--------
For each license in the source CSV:

1. If the license already has one or more current LTG assignments in IQ
   Server, those existing assignments are preserved.
2. If the license has no current LTG assignment in IQ Server, the LTG from the
   source CSV is used, as long as that LTG exists in the exported
   licenseThreatGroup data.
3. If the source CSV references an LTG name that does not exist in the IQ
   export, that license is skipped and reported.
4. If a license belongs to more than one current LTG in IQ Server, all of
   those current LTG mappings are preserved.

Required Input Files
--------------------
Before running this application, generate a support.zip from IQ Server and
extract the required JSON files from it.

Sonatype instructions for creating the support zip are here:
https://support.sonatype.com/hc/en-us/articles/223243768-How-to-Create-Sonatype-Server-Product-Support-Zip-Bundles#h_3d675639-6503-46fd-a2e7-90f78bc0f643

Within the extracted support.zip contents, the required files are located at:

- db/license.json
- db/licenseThreatGroupLicense.json
- db/licenseThreatGroup.json

Place the extracted files and the source CSV in the same directory as the
script, unless you plan to pass explicit paths on the command line:

- license.json
- licenseThreatGroupLicense.json
- licenseThreatGroup.json
- license_threat_groups_02272026.csv

The source CSV is expected to have no header row and to use this format:

license_id,license_threat_group_name

Files
-----
- reconcile_ltg.py
  The reconciliation script.

- ltg-updater-1.0.3.jar
  Optional local copy of the Sonatype LTG updater JAR. It is not required to
  run the reconciliation script.

To download the latest available LTG updater JAR and the latest source LTG CSV,
see the Sonatype community post:
https://community.sonatype.com/t/update-your-iq-server-license-threat-groups/3094

How To Run
----------
Open a terminal in this directory and run:

python3 reconcile_ltg.py

Example:

cd /Users/hardeepatkar/Development/Python/reconcileLTGS
python3 reconcile_ltg.py

Optional: show command-line help

python3 reconcile_ltg.py --help

Optional: run with explicit file paths

python3 reconcile_ltg.py \
  --licenses license.json \
  --assignments licenseThreatGroupLicense.json \
  --threat-groups licenseThreatGroup.json \
  --input-csv license_threat_groups_02272026.csv

Generated Output Files
----------------------
- license_threat_groups_reconciled.csv
  The CSV to import with the Sonatype LTG updater after reconciliation. This
  preserves existing IQ mappings and only uses the source CSV for licenses that
  do not already have an LTG assignment.

- license_threat_groups_reconciled_report.json
  Full machine-readable report describing the reconciliation results.

- license_threat_groups_changed_mappings.csv
  Licenses where the source CSV LTG differs from the current IQ mapping that
  was preserved.

- license_threat_groups_added_licenses.csv
  Licenses added from the source CSV because they had no current LTG
  assignment in IQ Server. This file also shows which LTG each one will be
  assigned to.

- license_threat_groups_unresolved.csv
  Licenses that could not be safely written because the current IQ mapping
  could not be fully resolved. This file may be empty.

Important Notes
---------------
- A single license can belong to more than one LTG in IQ Server. The script
  preserves all current LTG mappings for those licenses.
- Because multi-group mappings are preserved, the reconciled CSV can contain
  more rows than the source CSV.
- The script uses exact LTG names from licenseThreatGroup.json.
- If a source LTG name does not exist in licenseThreatGroup.json, that license
  will not be written to the reconciled CSV and will be listed in the report.

Typical Workflow
----------------
1. Generate a support.zip from IQ Server.
2. Extract these files from the support.zip:

   - db/license.json
   - db/licenseThreatGroupLicense.json
   - db/licenseThreatGroup.json

3. Place the extracted JSON files and the source LTG CSV in this directory.
4. Run:

   python3 reconcile_ltg.py

5. Review:

   - license_threat_groups_changed_mappings.csv
   - license_threat_groups_added_licenses.csv
   - license_threat_groups_unresolved.csv

6. Download the latest LTG updater JAR and latest Sonatype source LTG CSV from:

   https://community.sonatype.com/t/update-your-iq-server-license-threat-groups/3094

7. Import license_threat_groups_reconciled.csv using the latest LTG updater
   JAR.

Troubleshooting
---------------
If Python reports that a file is missing:
- Confirm you are running the script from this directory, or
- Pass explicit file paths with the command-line options.

If you want to validate the script syntax only:

python3 -m py_compile reconcile_ltg.py
