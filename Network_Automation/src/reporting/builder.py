from datetime import datetime


def build_report(compliance_results, inventory):

    report = {

        "run_metadata": {

            "timestamp": datetime.utcnow().isoformat(),

            "total_devices": len(inventory),

            "successful_runs": len(
                [
                    r for r in compliance_results
                    if r.get("status") != "FAILED"
                ]
            )

        },


        "devices": compliance_results,


        "summary": {

            "compliant": len(
                [
                    r for r in compliance_results
                    if r.get("status") == "COMPLIANT"
                ]
            ),


            "non_compliant": len(
                [
                    r for r in compliance_results
                    if r.get("status") == "NON-COMPLIANT"
                ]
            ),


            "failed": len(
                [
                    r for r in compliance_results
                    if r.get("status") == "FAILED"
                ]
            )

        }

    }

    return report