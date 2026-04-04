"""Quick API smoke test (run from repo root)."""
import os
import sys
from io import BytesIO

_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _root not in sys.path:
    sys.path.insert(0, _root)
os.environ.setdefault(
    "DATABASE_URL", "sqlite:///" + os.path.join(_root, "dev.db").replace("\\", "/")
)

from run import app

NESSUS = b"""<?xml version="1.0"?>
<NessusClientData_v2><Report>
<ReportHost name="10.0.0.1">
<HostProperties><tag name="host-fqdn">h.example.com</tag></HostProperties>
<ReportItem port="443" protocol="tcp" pluginID="12345" severity="4" pluginName="Critical Thing">
<cvss3_base_score>9.8</cvss3_base_score>
</ReportItem>
<ReportItem port="80" protocol="tcp" pluginID="999" severity="1" pluginName="Low Thing"/>
</ReportHost>
</Report></NessusClientData_v2>"""


def main():
    c = app.test_client()
    r = c.post(
        "/api/v1/scans/upload",
        data={"file": (BytesIO(NESSUS), "scan.nessus")},
        content_type="multipart/form-data",
    )
    print("upload", r.status_code, r.json)
    assert r.status_code == 201

    r2 = c.get("/api/v1/vulnerabilities?ip=10.0.0.1")
    print("vulns", r2.status_code, len(r2.json["vulnerabilities"]))
    assert r2.status_code == 200
    assert len(r2.json["vulnerabilities"]) == 2

    r3 = c.get("/api/v1/risk?ip=10.0.0.1")
    print("risk", r3.status_code, r3.json)
    assert r3.status_code == 200
    assert r3.json["risk_score"] == 5 + 1  # critical + low

    r4 = c.get("/api/v1/trends?granularity=weekly")
    print("trends", r4.status_code, r4.json)
    assert r4.status_code == 501  # SQLite

    print("smoke ok")


if __name__ == "__main__":
    main()
