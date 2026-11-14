"""Room stand-in: holds N GiB of incompressible memory, a loopback TCP pair,
an outbound TCP conn to the host, and a 1 s timer loop logging clocks."""
import os, socket, sys, threading, time

fill_gib = float(sys.argv[1])
host = sys.argv[2] if len(sys.argv) > 2 else ""
log = open("/work/state.log", "a", buffering=1)

blocks = []
chunk = 64 << 20
for _ in range(int(fill_gib * 1024 / 64)):
    blocks.append(os.urandom(chunk))

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 7000)); srv.listen(1)
cli = socket.create_connection(("127.0.0.1", 7000)); peer, _ = srv.accept()
ext = None
if host:
    try:
        ext = socket.create_connection((host, 9999), timeout=5); ext.settimeout(3)
    except OSError as e:
        log.write(f"ext connect failed {e}\n")

open("/work/ready", "w").write(str(time.time()))
n = 0
while True:
    n += 1
    lo = ex = "-"
    try:
        cli.sendall(b"ping"); lo = "ok" if peer.recv(4) == b"ping" else "bad"
    except OSError as e:
        lo = f"err:{e.errno}"
    if ext is not None:
        try:
            ext.sendall(b"ping\n"); r = ext.recv(5); ex = "ok" if r == b"ping\n" else f"bad:{r!r}"
        except OSError as e:
            ex = f"err:{e}"
    if os.path.exists("/work/touch"):
        t = time.monotonic(); acc = 0
        for b in blocks:
            acc ^= sum(b[::4096])
        os.unlink("/work/touch")
        log.write(f"touch {len(blocks)*64} MiB in {time.monotonic()-t:.3f}s acc={acc}\n")
    log.write(f"{n} mono={time.monotonic():.3f} wall={time.time():.3f} lo={lo} ext={ex}\n")
    time.sleep(1)
