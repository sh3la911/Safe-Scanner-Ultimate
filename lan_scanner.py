"""
LAN Scanner – Safe Scanner Ultimate
يفحص الشبكة المحلية عن منافذ RATs مفتوحة.
Read-only, safe.
"""
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# منافذ شائعة لأدوات التحكم
SUSPICIOUS_PORTS = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321]

def scan_port(ip, port, timeout=1.0):
    """فحص منفذ واحد على IP محدد."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((str(ip), port))
        sock.close()
        if result == 0:
            return (str(ip), port)
    except:
        pass
    return None

def scan_lan(progress_callback=None):
    """
    فحص الشبكة المحلية (نطاق 192.168.1.0/24 افتراضياً).
    يُرجع قائمة بالأجهزة التي لديها منافذ RAT مفتوحة.
    """
    results = []
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        # استخراج نطاق الشبكة
        parts = local_ip.split('.')
        if len(parts) == 4 and parts[0] in ('192', '10', '172'):
            network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        else:
            network = '192.168.1.0/24'
        net = ipaddress.ip_network(network, strict=False)
        hosts = list(net.hosts())
        total_hosts = len(hosts)
        scanned = 0
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for ip in hosts:
                for port in SUSPICIOUS_PORTS:
                    futures.append(executor.submit(scan_port, ip, port))
            for future in as_completed(futures):
                scanned += 1
                if progress_callback:
                    progress_callback(scanned, total_hosts * len(SUSPICIOUS_PORTS),
                                      f"فحص الشبكة... {int(scanned/(total_hosts*len(SUSPICIOUS_PORTS))*100)}%")
                res = future.result()
                if res:
                    ip, port = res
                    results.append({
                        "category": "Network Host",
                        "name": f"{ip}:{port}",
                        "path": ip,
                        "reasons": [f"منفذ RAT مفتوح: {port}"],
                        "score": 60,
                        "severity": "High"
                    })
    except Exception as e:
        results.append({
            "category": "LAN Scan",
            "name": "Error",
            "path": "",
            "reasons": [str(e)],
            "score": 0,
            "severity": "Low"
        })
    return results