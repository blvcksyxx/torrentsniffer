# 🌀 torrent_sniffer [v2]

A high-performance, real-time asynchronous network sniffer engineered to isolate and track **BitTorrent P2P swarm traffic**. Featuring a localized tactile Bento Grid terminal interface, dynamic web-noise filtering, and smart batch GeoIP resolution.

---

## ⚡ Overview

Unlike centralized platforms that route traffic through RTC media servers (e.g., Discord or Telegram), the BitTorrent protocol operates on pure, decentralized Peer-to-Peer architecture. To download a file, your client establishes direct TCP/UDP connections to other peers worldwide. 

**torrent_sniffer** hooks into your active network interface, cuts out background operating system noise, and isolates raw file-sharing payloads to visualize the exact IP addresses, geographic locations, and ISPs of peers inside your swarm in real time.

---

## 🛠️ Tech Stack & Key Features

* **Scapy Core:** Hooks directly into physical layer sockets to intercept raw UDP/TCP packet streams.
* **Smart Noise Filtration:** Automatically drops standard web traffic (Ports 80, 443) and system DNS/NTP loops to capture only genuine P2P file-sharing data layers.
* **Async Batch GeoIP Engine:** Bypasses rate limits and `429 Too Many Requests` bans by accumulating discovered IPs into a processing queue and resolving them in chunks of up to 100 per request via Post-Batch API.
* **Rich UI Bento Grid:** Sleek, scannable terminal interface with active sorting based on packet density and status.
* **Hotkeys Management:** On-the-fly filtering, cache clearing, and session resets without stopping the backend worker threads.

---

## 🎮 Interface Controls

| Key | Action | Description |
| :---: | :--- | :--- |
| **`f`** | **Filter Query** | Opens input prompt to search the active grid by City, Country, IP, or ISP on the fly. |
| **`c`** | **Clear Filter** | Removes the active filter and returns the layout to global monitoring. |
| **`r`** | **Reset Cache** | Instantly flushes the traffic table, geoip cache queue, and audio alerts. |
| **`q`** | **Quit Sockets** | Safely shuts down network workers and exits the application cleanly. |

---

## 🚀 Installation & Deployment

### 1. Clone the repository
```bash
git clone [https://github.com/blvcksyxx/torrentsniffer.git]([https://github.com/hellkyxx/torrent_sniffer.git](https://github.com/blvcksyxx/torrentsniffer.git))
cd torrentsniffer```
