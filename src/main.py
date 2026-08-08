from src.reports.manager import generate_manager_report
from src.reports.json_report import save_json_report
from src.process.manager import main_process
from src.reports.builder import build_report
def main():

    main_log = logging.LoggerAdapter(
        logger,
        {"dev": "MAIN"}
    )

    main_log.info("----- STARTING HYBRID AUTOMATION -----")

    compliance_results = []

    try:

        inventory, config_data = get_netbox()

        main_log.info(
            "----- NETBOX SYNC SUCCESSFUL -----"
        )


        tasks = []

        for device in inventory:

            ip = device.get("host")

            config = config_data.get(ip)

            tasks.append(
                {
                    "device": device,
                    "context": copy.deepcopy(config) if config else {}
                }
            )


        num_workers = min(len(tasks), 15)


        with ThreadPoolExecutor(
            max_workers=num_workers
        ) as executor:


            run_it = [
                executor.submit(
                    main_process,
                    task
                )
                for task in tasks
            ]


            for future in as_completed(run_it):

                try:

                    result = future.result()

                    compliance_results.append(
                        result
                    )


                except Exception as e:

                    main_log.error(
                        f"Device Thread Failed: {e}"
                    )

                    compliance_results.append(
                        {
                            "status": "FAILED",
                            "error": str(e)
                        }
                    )


        report = build_report(compliance_results, inventory)
        save_json_report(report)
        generate_manager_report(report)


        main_log.info(
            "Final Compliance Report Saved Successfully"
        )


    except Exception as e:

        main_log.exception(
            f"Main Automation Failed: {e}"
        )


    finally:

        final_log = logging.LoggerAdapter(
            logger,
            {"dev": "FINAL"}
        )

        final_log.info(
            "----- AUTOMATION COMPLETE -----"
        )
if __name__ == "__main__":
    main()
