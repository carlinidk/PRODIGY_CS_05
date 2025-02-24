import scapy.all as scapy
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time

sniff_thread = None
stop_sniffing = False
filter_option = "all"
packet_count = 0
start_time = None

def packet_sniffer(packet):
    global packet_count, start_time
    if stop_sniffing:
        return
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        proto = packet[scapy.IP].proto
        
        protocol_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, 'Other')
        payload = packet[scapy.IP].payload.summary() if packet[scapy.IP].payload else "No Payload"
        
        tree.insert("", tk.END, values=(src_ip, dst_ip, protocol_name, payload))
        packet_count += 1
        elapsed_time = time.time() - start_time if start_time else 1
        pps = round(packet_count / elapsed_time, 2)
        status_label.config(text=f"Capturing packets... ({packet_count} packets captured, {pps} PPS)", foreground="lime")

def start_sniffing():
    global sniff_thread, stop_sniffing, filter_option, packet_count, start_time
    stop_sniffing = False
    packet_count = 0
    start_time = time.time()
    tree.delete(*tree.get_children())  # Clear previous entries
    filter_map = {"all": "", "IP": "ip", "TCP": "tcp", "UDP": "udp", "ICMP": "icmp"}
    selected_filter = filter_map.get(filter_option, "")
    sniff_thread = threading.Thread(target=lambda: scapy.sniff(prn=packet_sniffer, store=False, filter=selected_filter), daemon=True)
    sniff_thread.start()
    status_label.config(text="Capturing packets...", foreground="lime")

def stop_sniffing_packets():
    global stop_sniffing
    stop_sniffing = True
    status_label.config(text="Capture stopped", foreground="red")

def set_filter(value):
    global filter_option
    filter_option = value

def clear_logs():
    tree.delete(*tree.get_children())
    status_label.config(text="Logs cleared", foreground="yellow")

def show_packet_details(event):
    selected_item = tree.selection()
    if selected_item:
        packet_info = tree.item(selected_item[0], "values")
        messagebox.showinfo("Packet Details", f"Source IP: {packet_info[0]}\nDestination IP: {packet_info[1]}\nProtocol: {packet_info[2]}\nPayload: {packet_info[3]}")

# GUI Setup
root = tk.Tk()
root.title("Network Packet Analyzer")
root.geometry("900x500")
root.configure(bg="#121212")  # Dark background

style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background="#1e1e1e", foreground="white", fieldbackground="#1e1e1e", rowheight=25)
style.configure("Treeview.Heading", background="#333333", foreground="cyan")
style.configure("TButton", background="#333333", foreground="white", padding=6)
style.configure("TLabel", background="#121212", foreground="white")

frame = ttk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

columns = ("Source IP", "Destination IP", "Protocol", "Payload")
tree = ttk.Treeview(frame, columns=columns, show="headings")

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, anchor="center")

# Scrollbars for Treeview
scroll_y = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
tree.configure(yscrollcommand=scroll_y.set)

tree.pack(fill=tk.BOTH, expand=True)
tree.bind("<Double-1>", show_packet_details)  # Bind double-click event to show packet details

control_frame = ttk.Frame(root)
control_frame.pack(fill=tk.X, padx=10, pady=5)

filter_label = ttk.Label(control_frame, text="Select Packet Filter:")
filter_label.pack(side=tk.LEFT, padx=5)

filter_options = ["all", "IP", "TCP", "UDP", "ICMP"]
filter_dropdown = ttk.Combobox(control_frame, values=filter_options, state="readonly")
filter_dropdown.current(0)
filter_dropdown.pack(side=tk.LEFT, padx=5)
filter_dropdown.bind("<<ComboboxSelected>>", lambda event: set_filter(filter_dropdown.get()))

def on_hover(event):
    event.widget.configure(style="Hover.TButton")

def on_leave(event):
    event.widget.configure(style="TButton")

style.configure("Hover.TButton", background="#00FFFF", foreground="black", padding=6)
style.map("Hover.TButton", background=[("active", "#00FFFF")], foreground=[("active", "black")])

start_button = ttk.Button(control_frame, text="Start Capture", command=start_sniffing, style="TButton")
start_button.pack(side=tk.LEFT, padx=5)
start_button.bind("<Enter>", on_hover)
start_button.bind("<Leave>", on_leave)

stop_button = ttk.Button(control_frame, text="Stop Capture", command=stop_sniffing_packets, style="TButton")
stop_button.pack(side=tk.LEFT, padx=5)
stop_button.bind("<Enter>", on_hover)
stop_button.bind("<Leave>", on_leave)

clear_button = ttk.Button(control_frame, text="Clear Logs", command=clear_logs, style="TButton")
clear_button.pack(side=tk.LEFT, padx=5)
clear_button.bind("<Enter>", on_hover)
clear_button.bind("<Leave>", on_leave)

# Status Bar
status_label = ttk.Label(root, text="Ready", background="#121212", foreground="white", anchor="w")
status_label.pack(fill=tk.X, padx=10, pady=5)

root.mainloop()
