import json
import os
import socket
import urllib.error
import urllib.request

HOST, PORT = "0.0.0.0", 3200


def _post_attack(source_ip: str) -> None:
    """Best-effort ship HL7 connection into Theriac attack memory."""
    api = (os.environ.get("THERIAC_API_URL") or os.environ.get("NEXT_PUBLIC_API_URL") or "").rstrip("/")
    if not api:
        return
    attacker = (os.environ.get("VULTR_ATTACKER_PUBLIC_IP") or "").split("/")[0]
    payload = {
        "device_model": os.environ.get("THERIAC_DEVICE_MODEL", "Philips_IntelliVue"),
        "attempted_port": PORT,
        "protocol": "TCP",
        "source_ip": source_ip,
        "event_type": "hl7_connection",
        "severity": "high" if source_ip == attacker else "medium",
        "firmware_version": os.environ.get("THERIAC_FIRMWARE", "L.0"),
        "reason": f"HL7 listener accepted connection from {source_ip}",
        "raw_summary": f"Connection from ('{source_ip}', ?)",
        "observation_source": "hl7_listener",
        "reachable": True,
    }
    try:
        req = urllib.request.Request(
            f"{api}/api/v1/attacks?run_immunity=true",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"[theriac] attack telemetry posted ({resp.status})")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"[theriac] attack telemetry post failed: {exc!r}")


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)
    print(f"Listening on {HOST}:{PORT}")
    while True:
        conn, addr = srv.accept()
        with conn:
            print(f"Connection from {addr}")
            _post_attack(addr[0])
            try:
                conn.settimeout(2)
                conn.recv(1024)
            except socket.timeout:
                pass
            except (ConnectionResetError, BrokenPipeError, OSError) as exc:
                print(f"Connection from {addr} ended early: {exc!r}")
                continue
            try:
                conn.sendall(b"MSH|^~\\&|PhilipsIntelliVue|HL7_ACK\r\n")
            except (ConnectionResetError, BrokenPipeError, OSError) as exc:
                print(f"Connection from {addr} closed before reply: {exc!r}")


if __name__ == "__main__":
    main()
