
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "app"))

from localstack_auditor import audit_local_s3

print(json.dumps(audit_local_s3(), indent=2))
