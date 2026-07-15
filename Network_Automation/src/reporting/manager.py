def generate_manager_report(report):

    metadata = report["run_metadata"]
    summary = report["summary"]

    with open("network_compliance_report.txt", "w") as f:

        f.write("=" * 60)
        f.write("\nNETWORK COMPLIANCE REPORT\n")
        f.write("=" * 60)

        f.write(
            f"\n\nReport Time: {metadata['timestamp']}"
        )

        f.write(
            f"\nDevices Audited: {metadata['total_devices']}"
        )

        f.write("\n\nSUMMARY")
        f.write("\n----------------")

        f.write(
            f"\nCompliant: {summary['compliant']}"
        )

        f.write(
            f"\nNon-Compliant: {summary['non_compliant']}"
        )

        f.write(
            f"\nFailed: {summary['failed']}"
        )

        f.write("\n\nDEVICE DETAILS")
        f.write("\n----------------")

        for device in report["devices"]:

            f.write(
                f"\n\nDevice: {device.get('device_name','Unknown')}"
            )

            f.write(
                f"\nStatus: {device.get('status')}"
            )

            if device.get("critical_issues"):

                f.write("\nIssues:")

                for issue in device["critical_issues"]:
                    f.write(
                        f"\n - {issue}"
                    )

            if device.get("actions_taken"):

                f.write("\nActions Taken:")

                for action in device["actions_taken"]:
                    f.write(
                        f"\n - {action}"
                    )