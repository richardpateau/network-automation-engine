from pathlib import Path
from dotenv import load_dotenv
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")
from src.reporting.manager import generate_manager_report
from src.reporting.technical import save_json_report
from src.reporting.builder import build_report
from src.process.manager import main_process
from src.sot.inventory import get_netbox
from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
import sys
import os
import logging
from src.core.settings import DRY_RUN

if "" in sys.path:
    sys.path.remove("")
if os.getcwd() in sys.path:
    sys.path.remove(os.getcwd())
sys.path.append(os.getcwd())


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    main_log = logging.LoggerAdapter(
        logger,
        {"dev": "MAIN"}
    )
    if os.getenv("SPLUNK_ENABLED", "false").lower() == "true":
        from src.utils.splunk_handler import SplunkHECHandler

        splunk_handler = SplunkHECHandler()
        splunk_handler.setLevel(logging.INFO)

        logging.getLogger().addHandler(splunk_handler)
        logging.getLogger().info(
            "Direct Splunk test",
            extra={
                "event_type": "python_logger_test",
                "component": "main",
                "device_ip": "10.10.10.10"
            }
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

            ip = device.get("device_ip")

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
