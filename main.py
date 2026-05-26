import os
import sys
import threading
import time
import requests
import keyboard
from scapy.all import sniff, UDP, TCP, IP, conf
from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.table import Table

if os.name == 'nt':
    import winsound

console = Console()

drop_isp_keywords = ["google", "cloudflare", "amazon", "microsoft", "digitalocean", "hetzner", "ovh", "fastly", "akamai"]

ip_traffic = {}
active_filter = ""
is_running = True
geoip_cache = {}
alerted_ips = set()
target_iface = None

# queue for batch geoip processing
ip_queue = set()
queue_lock = threading.Lock()

def geoip_worker():
    """background thread that processes accumulated IPs in chunks every 3 seconds"""
    global is_running
    while is_running:
        time.sleep(3.0)
        
        with queue_lock:
            if not ip_queue:
                continue
            # ip-api batch limits to 100 IPs per POST request
            chunk = list(ip_queue)[:100]
            for ip in chunk:
                ip_queue.remove(ip)
                
        if not chunk:
            continue
            
        try:
            # send payload as a json array of strings or objects
            response = requests.post("http://ip-api.com/batch?fields=query,country,city,org", json=chunk, timeout=5).json()
            
            for item in response:
                ip_str = item.get("query")
                if not ip_str:
                    continue
                country = item.get("country", "unknown").lower()
                city = item.get("city", "unknown").lower()
                
                geoip_cache[ip_str] = {
                    "location": f"{country}, {city}" if city != "unknown" else country,
                    "org": item.get("org", "unknown").lower()
                }
        except Exception as e:
            # if the batch call fails, return items to error state so they don't lock forever
            for ip_str in chunk:
                geoip_cache[ip_str] = {"location": "timeout/err", "org": "rate limit"}

def queue_geoip(ip_str):
    """safely add target IP into the async processing pool"""
    if ip_str in geoip_cache:
        return
        
    geoip_cache[ip_str] = {"location": "fetching...", "org": "queued"}
    with queue_lock:
        ip_queue.add(ip_str)

def process_packet(packet):
    """intercept and isolate raw torrent peer-to-peer streams"""
    global is_running
    if not is_running:
        return
    if packet.haslayer(IP) and (packet.haslayer(UDP) or packet.haslayer(TCP)):
        if packet.haslayer(TCP) and (packet[TCP].sport in [80, 443] or packet[TCP].dport in [80, 443]):
            return
        if packet.haslayer(UDP) and (packet[UDP].sport in [53, 123] or packet[UDP].dport in [53, 123]):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_len = len(packet)

        if 64 <= packet_len <= 1500:
            remote_ip = src_ip if not src_ip.startswith("192.168.") and not src_ip.startswith("127.") and not src_ip.startswith("10.") else dst_ip
            
            if remote_ip.startswith("192.168.") or remote_ip.startswith("127.") or remote_ip.startswith("10.") or remote_ip.startswith("224.") or remote_ip.startswith("239.") or remote_ip.startswith("0.") or remote_ip.startswith("255."):
                return

            if remote_ip in geoip_cache:
                isp_name = geoip_cache[remote_ip]["org"].lower()
                if any(kw in isp_name for kw in drop_isp_keywords):
                    return

            if remote_ip not in ip_traffic:
                ip_traffic[remote_ip] = {"packets": 0, "bytes": 0}
                queue_geoip(remote_ip)
            
            ip_traffic[remote_ip]["packets"] += 1
            ip_traffic[remote_ip]["bytes"] += packet_len

def generate_ui():
    """compile localized bento grid output layer"""
    flt_status = f"[bold green]{active_filter}[/]" if active_filter else "[dim]none[/]"
    
    if target_iface:
        iface_name = target_iface if isinstance(target_iface, str) else getattr(target_iface, "name", "unknown")
    else:
        iface_name = "default"
        
    table = Table(
        title=f"monitoring torrent swarm | interface: {iface_name.lower()} | filter: {flt_status}", 
        title_style="bold magenta", 
        expand=True
    )
    table.add_column("peer ip", style="cyan", no_wrap=True)
    table.add_column("location", style="purple")
    table.add_column("isp", style="blue")
    table.add_column("packets", style="yellow", justify="right")
    table.add_column("data", style="green", justify="right")
    table.add_column("status", justify="center")

    sorted_traffic = sorted(ip_traffic.items(), key=lambda x: x[1]["packets"], reverse=True)

    for ip, stats in sorted_traffic[:15]:
        geo = geoip_cache.get(ip, {"location": "loading...", "org": "loading..."})
        location = geo["location"]
        isp = geo["org"]

        if any(kw in isp.lower() for kw in drop_isp_keywords):
            continue

        if active_filter:
            search_zone = f"{ip} {location} {isp}".lower()
            if active_filter.lower() not in search_zone:
                continue

        if stats["packets"] > 50:
            status = "[bold pulse red]syncing[/]"
            if ip not in alerted_ips and os.name == 'nt' and geo["location"] not in ["fetching...", "timeout/err"]:
                alerted_ips.add(ip)
                threading.Thread(target=lambda: winsound.Beep(700, 150), daemon=True).start()
        else:
            status = "[dim]connected[/]"

        kb = round(stats["bytes"] / 1024, 1)
        table.add_row(ip, location, isp, str(stats["packets"]), f"{kb} kb", status)
        
    footer = r"[bold magenta]\[f][/] filter | [bold magenta]\[r][/] reset | [bold magenta]\[c][/] clear | [bold magenta]\[q][/] quit"
    return Panel(table, border_style="bright_blue", title="[bold green]@blvcksyxx torrent_sniffer [v2][/]", subtitle=footer)

def start_sniffing():
    """scapy socket listener targeting both tcp and udp streams"""
    sniff(iface=target_iface, prn=process_packet, store=0, stop_filter=lambda p: not is_running)

def main():
    global active_filter, ip_traffic, is_running, target_iface
    
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        console.print("[bold red][-] error: run application as administrator![/]")
        return

    os.system('cls' if os.name == 'nt' else 'clear')

    try:
        target_iface = conf.route.route("8.8.8.8")[0]
    except:
        target_iface = None

    # start backend networking loops
    threading.Thread(target=start_sniffing, daemon=True).start()
    threading.Thread(target=geoip_worker, daemon=True).start()
    
    console.print("[bold green][+] backend stack initialized successfully (batch geoip enabled).[/]")
    console.print("[bold green][+] sub to @blvcksyxx on telegram for more cool projects![/]")

    with Live(generate_ui(), refresh_per_second=4) as live:
        while is_running:
            live.update(generate_ui())
            time.sleep(0.25)
            
            if keyboard.is_pressed('f'):
                live.stop()
                console.print("\n" + "─" * 50)
                new_filter = console.input("[bold yellow][?] enter manual search query: [/]")
                active_filter = new_filter.strip().lower()
                console.print("─" * 50 + "\n")
                os.system('cls' if os.name == 'nt' else 'clear')
                live.start()
                
            elif keyboard.is_pressed('r'):
                with queue_lock:
                    ip_queue.clear()
                ip_traffic.clear()
                alerted_ips.clear()
                
            elif keyboard.is_pressed('c'):
                active_filter = ""
                os.system('cls' if os.name == 'nt' else 'clear')
                
            elif keyboard.is_pressed('q'):
                is_running = False
                live.stop()
                console.print("[bold red][!] shutting down network interface sockets...[/]")
                sys.exit(0)

if __name__ == "__main__":
    import ctypes
    main()