"""
MCP server for firmware-scan-service.

Exposes tools for registering firmware scans, querying scan status,
and managing the CVE vulnerability registry.

Requires the firmware-scan-service API to be running (default: http://localhost:8080).
"""

import os
import sys
import httpx
from mcp.server.fastmcp import FastMCP

API_BASE = os.getenv("FIRMWARE_SCAN_API", "http://localhost:8080")

mcp = FastMCP("firmware-scan-service")
client = httpx.Client(base_url=API_BASE, timeout=10.0)


# ---------------------------------------------------------------------------
# Scan tools
# ---------------------------------------------------------------------------

@mcp.tool()
def register_scan(
    device_id: str,
    firmware_version: str,
    binary_hash: str,
    metadata: dict | None = None,
) -> dict:
    """Register a device and its firmware for scanning.

    Submits a firmware scan request. If the same (device_id, binary_hash)
    has already been registered the existing record is returned without
    creating a duplicate scan job.

    Args:
        device_id: Unique identifier for the device (e.g. "device-abc123").
        firmware_version: Version string of the firmware (e.g. "2.1.4").
        binary_hash: SHA-256 hex digest of the firmware binary.
        metadata: Optional key/value metadata (max ~10 KB).

    Returns:
        The scan record including its id, status, and timestamps.
    """
    payload = {
        "device_id": device_id,
        "firmware_version": firmware_version,
        "binary_hash": binary_hash,
    }
    if metadata:
        payload["metadata"] = metadata

    resp = client.post("/v1/firmware-scans", json=payload)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Vulnerability tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_vulnerabilities() -> dict:
    """Return all CVE IDs currently in the vulnerability registry, sorted.

    Returns:
        A dict with a 'vulns' key containing a sorted list of CVE ID strings.
    """
    resp = client.get("/v1/findings/vulns")
    resp.raise_for_status()
    return resp.json()


@mcp.tool()
def report_vulnerabilities(cve_ids: list[str]) -> dict:
    """Add one or more CVE IDs to the global vulnerability registry.

    Duplicates are silently ignored. Each CVE is stored as an individual
    document keyed by its ID.

    Args:
        cve_ids: List of CVE ID strings (e.g. ["CVE-001", "CVE-042"]).

    Returns:
        The updated deduplicated list of all CVE IDs in the registry.
    """
    resp = client.patch("/v1/findings/vulns", json={"vulns": cve_ids})
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Diagnostic / convenience tools
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_status_summary() -> dict:
    """Return the count of firmware scans in each status.

    Queries the firmware_scans MongoDB collection via mongosh and returns
    counts for: scheduled, started, complete, failed.

    Returns:
        A dict mapping each status string to its count.
    """
    import subprocess
    script = (
        "var counts = {};"
        "['scheduled','started','complete','failed'].forEach(s => counts[s] = 0);"
        "db.firmware_scans.aggregate([{$group:{_id:'$status',n:{$sum:1}}}])"
        ".forEach(r => counts[r._id] = r.n);"
        "print(JSON.stringify(counts));"
    )
    result = subprocess.run(
        [
            "docker", "compose", "exec", "-T", "mongodb",
            "mongosh", "--quiet", "firmware_db", "--eval", script,
        ],
        capture_output=True,
        text=True,
        cwd=os.path.join(os.path.dirname(__file__), "..", "firmware-scan-service"),
    )
    if result.returncode != 0:
        raise RuntimeError(f"mongosh error: {result.stderr.strip()}")

    import json
    # mongosh may emit extra lines; find the JSON line
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise RuntimeError(f"Unexpected mongosh output: {result.stdout!r}")


@mcp.tool()
def top_vulnerabilities(limit: int = 5) -> list[dict]:
    """Return the CVEs with the highest detected_count, most frequent first.

    Args:
        limit: Maximum number of CVE records to return (default 5).

    Returns:
        List of vulnerability documents ordered by detected_count descending.
    """
    import subprocess, json
    script = (
        f"JSON.stringify(db.vulnerabilities.find({{}}).sort({{detected_count:-1}}).limit({limit}).toArray())"
    )
    result = subprocess.run(
        [
            "docker", "compose", "exec", "-T", "mongodb",
            "mongosh", "--quiet", "firmware_db", "--eval", script,
        ],
        capture_output=True,
        text=True,
        cwd=os.path.join(os.path.dirname(__file__), "..", "firmware-scan-service"),
    )
    if result.returncode != 0:
        raise RuntimeError(f"mongosh error: {result.stderr.strip()}")

    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if line.startswith("["):
            return json.loads(line)
    raise RuntimeError(f"Unexpected mongosh output: {result.stdout!r}")


if __name__ == "__main__":
    mcp.run(transport="stdio")