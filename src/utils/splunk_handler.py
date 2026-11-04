import logging
import os
import socket
import requests


class SplunkHECHandler(logging.Handler):

    def __init__(self):
        super().__init__()

        self.url = os.getenv("SPLUNK_HEC_URL")
        self.token = os.getenv("SPLUNK_HEC_TOKEN")
        self.index = os.getenv(
            "SPLUNK_INDEX",
            "network_automation"
        )

        if not self.url or not self.token:
            raise ValueError("Splunk HEC configuration is incomplete")

    def sanitize(self, data):

        sensitive = ("password", "secret", "token")

        if isinstance(data, dict):
            return {
                key: self.sanitize(value)
                for key, value in data.items()
                if not any(s in key.lower() for s in sensitive)
            }

        if isinstance(data, list):
            return [self.sanitize(item) for item in data]

        return data

    def emit(self, record):

        # Only forward deliberately structured events.
        if not getattr(record, "event_type", None):
            return

        try:
            standard_fields = {
                "name", "msg", "args", "levelname", "levelno",
                "pathname", "filename", "module", "exc_info",
                "exc_text", "stack_info", "lineno", "funcName",
                "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process"
            }

            event = {
                key: value
                for key, value in record.__dict__.items()
                if key not in standard_fields
            }

            event["message"] = record.getMessage()
            event["level"] = record.levelname

            payload = {
                "time": record.created,
                "host": socket.gethostname(),
                "source": "network-automation-engine",
                "sourcetype": "_json",
                "index": self.index,
                "event": self.sanitize(event)
            }

            response = requests.post(
                self.url,
                json=payload,
                headers={
                    "Authorization": f"Splunk {self.token}"
                },
                timeout=3
            )

            response.raise_for_status()

        except Exception:
            self.handleError(record)
