#!/usr/bin/env python3
from __future__ import annotations
import base64, hashlib, socket, struct, sys, time
from datetime import datetime
from typing import Dict, Generator, List, Optional, Tuple
import os
from dotenv import load_dotenv

load_dotenv()

def load_magic():
    raw = os.getenv("MAGIC")
    if raw is None:
        raise ValueError("MAGIC not found in .env")

    raw = raw.lower().replace("0x", "")

    b = bytes.fromhex(raw)

    magic_int = int.from_bytes(b, "little")

    return magic_int


def load_port():
    port_raw = os.getenv("PORT")
    if port_raw is None:
        raise ValueError("PORT not found in .env")
    return int(port_raw)

MAGIC = load_magic()
DEFAULT_PORT = load_port()
        

DEFAULT_PORT = load_port()
SOCKET_TIMEOUT = 15
READ_CHUNK = 65536
IDLE_AFTER_FIRST = 40
HARD_CAP_SECONDS = 90
PING_INTERVAL = 20

SERVICE_FLAGS = {
    1: "NODE_NETWORK",
    2: "NODE_GETUTXO",
    4: "NODE_BLOOM",
    8: "NODE_WITNESS",
    16: "NODE_XTHIN",
    64: "NODE_COMPACT_FILTERS",
    1024: "NODE_NETWORK_LIMITED",
}
NET_IPV4, NET_IPV6, NET_TORV3, NET_I2P, NET_CJDNS = 1, 2, 4, 5, 6
NETWORK_NAMES = {
    NET_IPV4: "IPv4",
    NET_IPV6: "IPv6",
    NET_TORV3: "TorV3",
    NET_I2P: "I2P",
    NET_CJDNS: "CJDNS",
}

def decode_services(services: int) -> List[str]:
    return [n for f, n in SERVICE_FLAGS.items() if services & f] or ["NONE"]

def sha256d(b: bytes) -> bytes:
    import hashlib as _h
    return _h.sha256(_h.sha256(b).digest()).digest()

def ip6_from_ipv4(ipv4: str) -> bytes:
    return b"\x00"*10 + b"\xff\xff" + socket.inet_aton(ipv4)

def read_compact_size(buf: memoryview, off: int) -> Tuple[Optional[int], int]:
    if off >= len(buf): return None, 0
    b0 = buf[off]
    if b0 < 0xFD:  return b0, off+1
    if b0 == 0xFD: return struct.unpack_from("<H", buf, off+1)[0], off+3
    if b0 == 0xFE: return struct.unpack_from("<I", buf, off+1)[0], off+5
    return struct.unpack_from("<Q", buf, off+1)[0], off+9

def build_msg(cmd: str, payload: bytes) -> bytes:
    name = cmd.encode("ascii")
    if len(name) > 12: raise ValueError("command too long")
    header = struct.pack("<I", MAGIC) + name + b"\x00"*(12-len(name))
    header += struct.pack("<I", len(payload)) + sha256d(payload)[:4]
    return header + payload

def build_version_payload() -> bytes:
    version= 70016; services = 0; ts = int(time.time())
    nonce = int.from_bytes(sha256d(str(ts).encode())[:8], "little")
    ua = b"/connector/"
    payload  = struct.pack("<iQq", version, services, ts)
    payload += struct.pack("<Q", services) + ip6_from_ipv4("0.0.0.0") + struct.pack(">H", DEFAULT_PORT)
    payload += struct.pack("<Q", services) + ip6_from_ipv4("0.0.0.0") + struct.pack(">H", 0)
    payload += struct.pack("<Q", nonce)
    payload += bytes([len(ua)]) + ua
    payload += struct.pack("<i", 0) + b"\x00" 
    return payload

def build_ping_payload(nonce: int) -> bytes:
    return struct.pack("<Q", nonce)


def messages_from_stream(buf: bytearray) -> Generator[Tuple[str, bytes], None, None]:
    pos = 0
    while True:
        total = len(buf)
        if pos + 24 > total: break
        mv = memoryview(buf)
        magic, = struct.unpack_from("<I", mv, pos)
        if magic != MAGIC:
            pos += 1; mv.release(); continue
        cmd = bytes(mv[pos+4:pos+16]).rstrip(b"\x00").decode("ascii", "ignore")
        mlen, = struct.unpack_from("<I", mv, pos+16)
        checksum = bytes(mv[pos+20:pos+24])
        end = pos + 24 + mlen
        if end > total: mv.release(); break
        payload = bytes(mv[pos+24:end]); mv.release()
        if sha256d(payload)[:4] != checksum:
            pos += 1; continue
        yield (cmd, payload)
        pos = end
    if pos: del buf[:pos]


def decode_addr(payload: bytes) -> List[Dict]:
    out: List[Dict] = []
    mv = memoryview(payload); off = 0
    count, off = read_compact_size(mv, off)
    if not count: return out
    for _ in range(count):
        if off + 30 > len(payload): break
        last_seen, = struct.unpack_from("<I", mv, off)
        services,  = struct.unpack_from("<Q", mv, off+4)
        ip_raw = bytes(mv[off+12:off+28]); port, = struct.unpack_from(">H", mv, off+28)
        if ip_raw.startswith(b"\x00"*10 + b"\xff\xff"):
            ip = socket.inet_ntoa(ip_raw[12:]); net = "IPv4"
        else:
            ip = socket.inet_ntop(socket.AF_INET6, ip_raw); net = "IPv6"
        out.append({
            "last_seen": last_seen,
            "services": services,
            "services_decoded": decode_services(services),
            "network": net,
            "ip": ip,
            "port": port,
        })
        off += 30
    return out

def decode_addrv2(payload: bytes) -> List[Dict]:
    out: List[Dict] = []
    mv = memoryview(payload); off = 0
    count, off = read_compact_size(mv, off)
    if not count: return out
    for _ in range(count):
        if off + 4 > len(payload): break
        last_seen = struct.unpack_from("<I", mv, off)[0]; off += 4
        services, off = read_compact_size(mv, off)
        if services is None or off + 1 > len(payload): break
        net_id = mv[off]; off += 1
        addr_len, off = read_compact_size(mv, off)
        if addr_len is None or off + addr_len + 2 > len(payload): break
        addr_bytes = bytes(mv[off:off+addr_len]); off += addr_len
        port, = struct.unpack_from(">H", mv, off); off += 2
        if net_id == NET_IPV4:
            ip = socket.inet_ntoa(addr_bytes)
        elif net_id == NET_IPV6:
            ip = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        elif net_id == NET_TORV3:
            chk = hashlib.sha3_256(b".onion checksum" + addr_bytes + b"\x03").digest()[:2]
            ip = base64.b32encode(addr_bytes + chk + b"\x03").decode().lower() + ".onion"
        elif net_id == NET_I2P:
            ip = base64.b32encode(addr_bytes).decode().lower() + ".b32.i2p"
        elif net_id == NET_CJDNS:
            ip = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        else:
            ip = f"Unknown-{net_id}"
        out.append({
            "last_seen": last_seen,
            "services": services,
            "services_decoded": decode_services(services),
            "network": NETWORK_NAMES.get(net_id, f"Unknown-{net_id}"),
            "ip": ip,
            "port": port,
        })
    return out

class DogeLiveScanner:
    def __init__(self, host: str, port: int = DEFAULT_PORT):
        self.host, self.port = host, port
        self.sock: Optional[socket.socket] = None
        self.buf = bytearray()
        self.remote_ip, self.remote_port = host, port
        self.last_ping = 0.0; self.ping_nonce = 0
        self.collected: List[Dict] = []
        self.first_nonself_time = None; self.last_new_time = None

    def _is_self_ad(self, peers: List[Dict]) -> bool:
        return len(peers) == 1 and peers[0]["ip"] == self.remote_ip and peers[0]["port"] in (self.remote_port, DEFAULT_PORT)

    def connect(self) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(SOCKET_TIMEOUT); s.connect((self.host, self.port))
            self.sock = s
            self.remote_ip, self.remote_port = s.getpeername()
            return True
        except Exception as e:
            print(f"[!] Connection failed: {e}"); return False

    def _send(self, cmd: str, payload: bytes = b""):
        if not self.sock: return
        try: self.sock.sendall(build_msg(cmd, payload))
        except Exception: pass

    def _maybe_ping(self):
        now = time.time()
        if now - self.last_ping > PING_INTERVAL:
            self.ping_nonce = (self.ping_nonce + 1) & 0xFFFFFFFFFFFFFFFF
            self._send("ping", build_ping_payload(self.ping_nonce))
            self.last_ping = now

    def handshake(self):
        self._send("version", build_version_payload())
        seen_version = seen_verack = False
        deadline = time.time() + SOCKET_TIMEOUT
        while time.time() < deadline and not (seen_version and seen_verack):
            try:
                chunk = self.sock.recv(READ_CHUNK)
                if not chunk: break
                self.buf += chunk
                for cmd, payload in messages_from_stream(self.buf):
                    if cmd == "version":
                        seen_version = True; self._send("verack", b"")
                    elif cmd == "verack":
                        seen_verack = True
                    elif cmd == "ping" and len(payload) == 8:
                        self._send("pong", payload)
            except socket.timeout:
                break
        self._send("getaddr", b"")

    def _augment_rows(self, parsed: List[Dict]) -> List[Dict]:
        recv_ts = int(time.time())
        recv_iso = datetime.now().astimezone().isoformat()
        rows = []
        for p in parsed:
            rows.append({
                "timestamp": recv_ts,               
                "time": recv_iso,                  
                "last_seen": p["last_seen"],       
                "services": p["services"],
                "services_decoded": p["services_decoded"],
                "network": p["network"],
                "source_ip": self.remote_ip,
                "source_port": self.remote_port,
                "destination_ip": p["ip"],
                "destination_port": p["port"],
            })
        return rows

    def run(self) -> Optional[List[Dict]]:
        if not self.sock: return None
        start = time.time()
        try:
            while True:
                if self.first_nonself_time and self.last_new_time and time.time() - self.last_new_time > IDLE_AFTER_FIRST:
                    break
                if time.time() - start > HARD_CAP_SECONDS:
                    break
                self.sock.settimeout(1.0)
                try:
                    chunk = self.sock.recv(READ_CHUNK)
                    if not chunk: break
                    self.buf += chunk
                    for cmd, payload in messages_from_stream(self.buf):
                        if cmd in ("addr", "addrv2"):
                            parsed = decode_addr(payload) if cmd == "addr" else decode_addrv2(payload)
                            if not parsed or self._is_self_ad(parsed):
                                continue
                            rows = self._augment_rows(parsed)
                            self.collected.extend(rows)
                            self.last_new_time = time.time()
                            if not self.first_nonself_time: self.first_nonself_time = time.time()
                        elif cmd == "ping" and len(payload) == 8:
                            self._send("pong", payload)
                except socket.timeout:
                    self._maybe_ping(); continue
        except Exception as e:
            print(f"[!] Runtime error: {e}")
        finally:
            self.close()
        return self.collected or None

    def close(self):
        try:
            if self.sock: self.sock.close()
        except Exception: pass
        self.sock = None

def scan_peer(host: str, port: int = DEFAULT_PORT) -> Optional[List[Dict]]:
    cli = DogeLiveScanner(host, port)
    if not cli.connect(): return None
    print(f"[+] Connected to {host}:{port}")
    cli.handshake()
    return cli.run()

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "185.252.234.250"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    rows = scan_peer(host, port)
    if not rows:
        print("[-] No peers found.")
    else:
        print(f"[+] Rows: {len(rows)}")
        for r in rows[:5]:
            print(r)