# 📡 Network Packet Sniffer

A terminal-based network packet sniffer developed in Python. It captures, decodes, and displays real-time network traffic, including IP, TCP, UDP, and ICMP packet headers. This tool is excellent for understanding networking fundamentals and learning how data flows through systems.

---

## 🔍 Features

- Real-time packet capture from network interfaces
- Decodes Ethernet, IP, TCP, UDP, and ICMP headers
- Displays source and destination IPs, ports, and protocol details
- Modular code structure for easy extension
- Educational tool for learning about network protocols and packet structures

---

## 🛠️ Tech Stack

- **Language:** Python 3
- **Libraries:** `socket`, `struct`
- **Concepts:** Raw sockets, OSI model, network protocols

---

## 🚀 Getting Started

### Prerequisites

- Python 3.x installed on your system
- Administrator/root privileges to run raw socket operations

### Installation

```bash
# Clone the repository
git clone https://github.com/KomalMaurya/packet-sniffer.git

# Navigate to the project directory
cd packet-sniffer

# Run the sniffer script with administrative privileges
sudo python3 sniffer.py
```

> Use `Ctrl + C` to stop the packet sniffer.

---

## 🧪 Sample Output

```plaintext
[+] Packet captured:
Source IP: 192.168.1.2 | Destination IP: 142.250.195.238
Protocol: TCP | Source Port: 53841 | Dest Port: 443
...
```
## 🖥️ GUI Preview
![Packet Sniffer GUI](https://github.com/user-attachments/assets/ef2c029a-abbd-4d98-94b9-125d85fea1af)



---

## 📁 Project Structure

```plaintext
packet-sniffer/
├── NetworkPacketSniffer.py
├── packetSniffer.py
├── README.md
└── ...
```

- `packetSniffer.py`: Main script to start the packet sniffer
- `README.md`: Project documentation

---

## ⚠️ Disclaimer

This project is intended **strictly for educational purposes**. Unauthorized packet sniffing on networks without permission is illegal and unethical. Use responsibly.

---

## 🤝 Contributing

Contributions are welcome! Feel free to fork the repository and submit pull requests.

---

## 📫 Contact

- 📧 Email: [komal092btcseai23@igdtuw.ac.in](mailto:komal092btcseai23@igdtuw.ac.in)
- 🐙 GitHub: [@KomalMaurya](https://github.com/KomalMaurya)

---

## ⭐️ Support

If you find this project helpful, please give it a ⭐️ on GitHub!

---

> "Sniff responsibly. 🕵️‍♀️"
