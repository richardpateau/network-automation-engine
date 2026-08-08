import json
from pathlib import Path


def save_json_report(report, filename="final_compliance_report.json"):

    report_path = Path(filename)

    with report_path.open("w") as f:
        json.dump(
            report,
            f,
            indent=4,
            default=str
        )

    return str(report_path)