import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import csv

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("⚡ Windows Packet Sniffer")
        self.root.geometry("1050x620")
        self.root.configure(bg="#f5f5f5")

        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Treeview",
                        background="#ffffff",
                        foreground="black",
                        rowheight=25,
                        fieldbackground="#f5f5f5",
                        font=('Segoe UI', 10))
        style.map('Treeview', background=[('selected', '#87CEEB')])

        self.tree = ttk.Treeview(root, columns=("Protocol", "Source", "Destination", "Info"), show='headings')
        for col in ("Protocol", "Source", "Destination", "Info"):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=200 if col != "Info" else 350, anchor='center')

        self.tree.pack(padx=20, pady=(20, 10), fill=tk.BOTH, expand=True)

        btn_frame = tk.Frame(root, bg="#f5f5f5")
        btn_frame.pack(pady=10)

        self.start_btn = tk.Button(btn_frame, text="▶ Start Sniffing", bg="#4CAF50", fg="white",
                                   font=('Segoe UI', 10, 'bold'), width=15, command=self.start_sniffing)
        self.start_btn.pack(side=tk.LEFT, padx=10)

        self.stop_btn = tk.Button(btn_frame, text="■ Stop Sniffing", bg="#f44336", fg="white",
                                  font=('Segoe UI', 10, 'bold'), width=15, command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=10)

        self.export_btn = tk.Button(btn_frame, text="⬇ Export to CSV", bg="#2196F3", fg="white",
                                    font=('Segoe UI', 10, 'bold'), width=15, command=self.export_csv)
        self.export_btn.pack(side=tk.LEFT, padx=10)

        self.sniffing = False
        self.captured_packets = []

    def start_sniffing(self):
        self.sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def sniff_packets(self):
        def process_packet(packet):
            if not self.sniffing:
                return False

            proto = "-"
            src = "-"
            dst = "-"
            info = "-"

            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                if TCP in packet:
                    proto = "TCP"
                    info = f"{packet[TCP].sport} → {packet[TCP].dport}"
                elif UDP in packet:
                    proto = "UDP"
                    info = f"{packet[UDP].sport} → {packet[UDP].dport}"
                elif ICMP in packet:
                    proto = "ICMP"
                    info = f"Type {packet[ICMP].type} Code {packet[ICMP].code}"
                else:
                    proto = "Other"

                # Schedule UI + data update safely in main thread
                self.root.after(0, self.insert_packet, proto, src, dst, info)

        sniff(prn=process_packet, store=False)

    def insert_packet(self, proto, src, dst, info):
        self.captured_packets.append((proto, src, dst, info))
        self.tree.insert('', 'end', values=(proto, src, dst, info))

    def export_csv(self):
        if not self.captured_packets:
            print("No packets to export.")
            return

        try:
            with open("captured_packets.csv", "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Protocol", "Source", "Destination", "Info"])
                writer.writerows(self.captured_packets)
            print("✅ Packets exported to captured_packets.csv")
        except Exception as e:
            print("❌ Error exporting:", e)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
