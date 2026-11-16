import socket, threading, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], 9999)); s.listen(8)
def h(c):
    with c:
        while True:
            d = c.recv(4096)
            if not d: print("peer closed", flush=True); return
            c.sendall(d)
while True:
    c, a = s.accept(); print("conn", a, flush=True); threading.Thread(target=h, args=(c,), daemon=True).start()
