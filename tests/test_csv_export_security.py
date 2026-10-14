"""CSV formula injection defenses for spreadsheet consumers."""
import csv
import io

import pytest

from networkpulse.security.csv_safety import safe_spreadsheet_cell


@pytest.mark.parametrize("payload", [
    "=1+1", "+SUM(A1)", "-2+3", "@SUM(A1:A2)",
    "  =HYPERLINK(1,2)", "\t=2+2", "\r\n@SUM(A1)",
    "\ufeff=4", "\u200b=5",
])
def test_dangerous_exported_text_never_begins_with_formula(payload):
    sanitized = safe_spreadsheet_cell(payload)
    assert sanitized.startswith("'")
    buffer = io.StringIO()
    csv.writer(buffer).writerow([sanitized])
    decoded = next(csv.reader(io.StringIO(buffer.getvalue())))
    assert decoded[0].startswith("'")


def test_safe_cells_preserve_valid_csv_values():
    assert safe_spreadsheet_cell("analyst-one") == "analyst-one"
    assert safe_spreadsheet_cell("198.51.100.7") == "198.51.100.7"
    assert safe_spreadsheet_cell(None) is None
    assert safe_spreadsheet_cell(123) == 123


def test_actual_soc_export_escapes_attacker_controlled_assignee(client, app_settings, samples):
    headers = {"X-API-Key": app_settings.api_key}
    payload = {"events": [e.model_dump(mode="json") for e in samples[-70:]]}
    posted = client.post("/api/v1/ingest", json=payload, headers=headers)
    assert posted.status_code == 200
    alert = client.get("/api/v1/alerts").json()[0]["id"]
    malicious_name = "  =HYPERLINK(1,2)"
    updated = client.patch(
        f"/api/v1/alerts/{alert}/assignment", headers=headers,
        json={"assigned_to": malicious_name, "note": "investigate this flow"}
    )
    assert updated.status_code == 200
    exported = client.get("/api/v1/alerts/export.csv")
    assert exported.status_code == 200
    rows = list(csv.DictReader(io.StringIO(exported.text)))
    assert any(row["assigned_to"] == "'" + malicious_name for row in rows)
