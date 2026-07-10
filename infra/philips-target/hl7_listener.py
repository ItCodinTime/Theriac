import socket

HOST, PORT = "0.0.0.0", 3200


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
            try:
                conn.settimeout(2)
                conn.recv(1024)
            except socket.timeout:
                # Normal path for a client that just connects and waits
                # (e.g. `nc host 3200`, or any probe that doesn't send
                # anything) -- fall through and still send the ACK banner.
                pass
            except (ConnectionResetError, BrokenPipeError, OSError) as exc:
                # Peer already tore its socket down before we could even
                # finish recv(). Nothing to reply to -- skip sendall() and
                # move on to the next connection instead of crashing.
                print(f"Connection from {addr} ended early: {exc!r}")
                continue
            # Trivial placeholder HL7-style ACK banner. Kept in its own try:
            # a client that connects and disconnects immediately without
            # reading anything (e.g. a plain reachability probe) can make
            # this race an already-torn-down peer. Guard it independently
            # from the recv() timeout above so a normal recv() timeout
            # still always results in the banner being sent.
            try:
                conn.sendall(b"MSH|^~\\&|PhilipsIntelliVue|HL7_ACK\r\n")
            except (ConnectionResetError, BrokenPipeError, OSError) as exc:
                print(f"Connection from {addr} closed before reply: {exc!r}")


if __name__ == "__main__":
    main()
