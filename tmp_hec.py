# tmp_log.py
import logging, traceback
from dotenv import load_dotenv; load_dotenv()
from src.utils.splunk_handler import SplunkHECHandler

class LoudHEC(SplunkHECHandler):
    def handleError(self, record):
        traceback.print_exc()

logging.basicConfig(level=logging.INFO)
logging.getLogger().addHandler(LoudHEC())
log = logging.getLogger("src.test")

print("--- test 1: should work")
log.info("t1", extra={"event_type": "t1", "vlan_name": "x"})

print("--- test 2: your real call shape, with 'name'")
try:
    log.info("t2", extra={"event_type": "t2", "name": "x"})
except Exception:
    traceback.print_exc()

print("--- test 3: through a plain LoggerAdapter")
adp = logging.LoggerAdapter(log, {"dev": "1.1.1.1"})
adp.info("t3", extra={"event_type": "t3"})