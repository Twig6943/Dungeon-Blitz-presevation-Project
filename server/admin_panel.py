# admin_panel.py
import json
import os
import struct
import inspect
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from BitUtils import BitBuffer

DATA_FOLDER = "data"
PACKETS_FILE = os.path.join(DATA_FOLDER, "packet_types.json")

if not os.path.exists(DATA_FOLDER):
    os.makedirs(DATA_FOLDER)

# Initialize packets JSON file if missing
if not os.path.exists(PACKETS_FILE):
    with open(PACKETS_FILE, "w") as f:
        json.dump({}, f, indent=4)

def build_custom_packet(method_calls, pkt_type):
    bb = BitBuffer(debug=True)
    for method_name, args in method_calls:
        method = getattr(bb, method_name, None)
        if not method:
            raise ValueError(f"Unknown BitBuffer method: {method_name}")
        # Call with argument list
        if isinstance(args, (tuple, list)):
            method(*args)
        else:
            method(args)
    payload = bb.to_bytes()
    header = struct.pack(">HH", pkt_type, len(payload))
    return header + payload

def get_bitbuffer_methods():
    return sorted(
        name
        for name, fn in inspect.getmembers(BitBuffer, predicate=inspect.isfunction)
        if name.startswith("write_")
    )

class AdminPanel(tk.Tk):
    def __init__(self, sessions_getter):
        super().__init__()
        self.sessions_getter = sessions_getter
        self.title("Admin Panel")
        self.geometry("700x550")
        self.buffer_rows = []
        self.method_suggestions = get_bitbuffer_methods()
        self.packets_data = self.load_packets_data()
        self.create_widgets()
        self.bind_keys()

    def bind_keys(self):
        # Enter = send current packet
        self.bind("<Return>", lambda e: self.send_packet())

        # Placeholder bindings for existing buttons
        self.bind("<Control-n>", lambda e: self.add_buffer_row())  # Ctrl+N = Add Buffer Row
        self.bind("<Control-s>", lambda e: self.save_packet())  # Ctrl+S = Save Packet
        self.bind("<Control-l>", lambda e: self.load_packet())  # Ctrl+L = Load Packet

        # Future placeholders (you can change these when you add sub-packet support)
        self.bind("<Control-a>", lambda e: print("Ctrl+A pressed (placeholder)"))
        self.bind("<Control-e>", lambda e: print("Ctrl+E pressed (placeholder)"))

    def create_widgets(self):
        # Saved packets dropdown
        top_frame = tk.Frame(self)
        top_frame.pack(pady=5)
        tk.Label(top_frame, text="Saved Packets:").pack(side=tk.LEFT)
        self.saved_pkt_var = tk.StringVar()
        self.saved_pkt_menu = ttk.Combobox(
            top_frame,
            textvariable=self.saved_pkt_var,
            values=list(self.packets_data.keys()),
            width=40,
            state="readonly"
        )
        self.saved_pkt_menu.pack(side=tk.LEFT, padx=5)
        self.saved_pkt_menu.bind("<<ComboboxSelected>>", self.load_selected_packet)

        # Loop controls
        loop_frame = tk.Frame(self)
        loop_frame.pack(pady=5, anchor="w")

        self.loop_var = tk.BooleanVar(value=False)
        self.loop_delay_var = tk.StringVar(value="1")  # default 1 second

        tk.Checkbutton(loop_frame, text="Loop Packet", variable=self.loop_var).pack(side=tk.LEFT, padx=5)
        tk.Label(loop_frame, text="Delay (s):").pack(side=tk.LEFT, padx=2)
        tk.Entry(loop_frame, textvariable=self.loop_delay_var, width=5).pack(side=tk.LEFT, padx=5)

        # Packet type centered
        type_frame = tk.Frame(self)
        type_frame.pack(pady=5)
        tk.Label(type_frame, text="Packet Type (hex):").pack(side=tk.LEFT)
        self.pkt_type_var = tk.StringVar(value="F5")
        tk.Entry(type_frame, textvariable=self.pkt_type_var, width=6, justify='center').pack(side=tk.LEFT, padx=5)

        # Description
        desc_frame = tk.Frame(self)
        desc_frame.pack(pady=5, fill=tk.X)
        tk.Label(desc_frame, text="Description:").pack(side=tk.LEFT)
        self.desc_var = tk.StringVar()
        tk.Entry(desc_frame, textvariable=self.desc_var, width=60).pack(side=tk.LEFT, padx=5)

        # Buffer rows
        self.rows_frame = tk.Frame(self)
        self.rows_frame.pack(pady=10, fill=tk.X)
        self.add_buffer_row()

        # Action buttons
        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=10, fill=tk.X)

        # Left side: Add row & Send
        left_btn_frame = tk.Frame(btn_frame)
        left_btn_frame.pack(side=tk.LEFT)
        tk.Button(left_btn_frame, text="Add Buffer Row", command=self.add_buffer_row).pack(side=tk.LEFT, padx=5)
        tk.Button(left_btn_frame, text="Send Packet", command=self.send_packet).pack(side=tk.LEFT, padx=5)

        # Right side: Save/Load
        right_btn_frame = tk.Frame(btn_frame)
        right_btn_frame.pack(side=tk.RIGHT)
        tk.Button(right_btn_frame, text="Save Packet", command=self.save_packet).pack(side=tk.LEFT, padx=5)
        tk.Button(right_btn_frame, text="Load Packet", command=self.load_packet).pack(side=tk.LEFT, padx=5)

        # Status label
        self.status_var = tk.StringVar()
        self.status_label = tk.Label(self, textvariable=self.status_var, anchor="w", fg="blue")
        self.status_label.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=5)



    def add_buffer_row(self, method="", value="", hint=""):
        row_frame = tk.Frame(self.rows_frame)
        row_frame.pack(fill=tk.X, pady=2)

        method_var = tk.StringVar(value=method)
        value_var = tk.StringVar(value=value)
        hint_var = tk.StringVar(value=hint)  # New hint variable

        # Method Combobox
        ttk.Combobox(
            row_frame,
            textvariable=method_var,
            values=self.method_suggestions,
            width=30
        ).pack(side=tk.LEFT, padx=5)

        # Buffer value Entry
        tk.Entry(row_frame, textvariable=value_var, width=20).pack(side=tk.LEFT, padx=5)

        # Remove button
        remove_btn = tk.Button(row_frame, text="Remove",
                               command=lambda: self.remove_buffer_row(row_frame, method_var, value_var, hint_var))
        remove_btn.pack(side=tk.LEFT, padx=5)

        # Hint label + entry
        tk.Label(row_frame, text="hint:").pack(side=tk.LEFT, padx=(10, 2))  # small label
        tk.Entry(row_frame, textvariable=hint_var, width=30, fg="gray").pack(side=tk.LEFT, padx=5)

        # Save row data including hint
        self.buffer_rows.append((row_frame, method_var, value_var, hint_var))

    def remove_buffer_row(self, row_frame, method_var, value_var, hint_var):
        """Remove a buffer row from the UI and the tracking list"""
        row_frame.destroy()
        self.buffer_rows = [r for r in self.buffer_rows if r[1] != method_var]

    def send_packet(self):
        def _send():
            try:
                pkt_type = int(self.pkt_type_var.get(), 16)
                method_calls = []
                for _, mvar, vvar, _ in self.buffer_rows:  # ignore hint
                    method = mvar.get().strip()
                    val_str = vvar.get().strip()
                    if not method or not val_str:
                        continue
                    parts = [p.strip() for p in val_str.split(",")]
                    args = []
                    for p in parts:
                        if p == "":
                            continue
                        try:
                            if "." in p:
                                args.append(float(p))
                            else:
                                args.append(int(p))
                        except ValueError:
                            args.append(p)
                    if len(args) == 1:
                        args = args[0]
                    method_calls.append((method, args))
                if not method_calls:
                    self.status_var.set("No buffers to send.")
                    return
                packet = build_custom_packet(method_calls, pkt_type)

                while True:
                    for session in list(self.sessions_getter()):
                        try:
                            session.conn.sendall(packet)
                            print(f"[Admin] Sent packet to {session.addr}")
                        except Exception as e:
                            print(f"[Admin] Failed to send packet to {session.addr}: {e}")
                    self.status_var.set(f"Packet 0x{pkt_type:X} sent to all clients.")

                    if not self.loop_var.get():
                        break  # stop loop if loop checkbox is unchecked

                    try:
                        delay = float(self.loop_delay_var.get())
                    except ValueError:
                        delay = 1.0  # fallback delay
                    time.sleep(delay)

            except Exception as e:
                self.status_var.set(f"Error: {str(e)}")

        # Run sending in a separate thread to avoid freezing the GUI
        threading.Thread(target=_send, daemon=True).start()

    def load_packets_data(self):
        with open(PACKETS_FILE, "r") as f:
            return json.load(f)

    def save_packets_data(self):
        with open(PACKETS_FILE, "w") as f:
            json.dump(self.packets_data, f, indent=4)

    def save_packet(self):
        selected_name = self.saved_pkt_var.get()

        # If a packet is selected, ask whether to overwrite or create new
        if selected_name and selected_name in self.packets_data:
            response = messagebox.askyesnocancel(
                "Save Packet",
                f"A packet named '{selected_name}' is selected.\n"
                "Yes = Overwrite\nNo = Create New\nCancel = Abort"
            )
            if response is None:
                # Cancel pressed
                return
            elif response:
                # Yes = Overwrite
                name = selected_name
            else:
                # No = Create new
                name = tk.simpledialog.askstring("Save Packet", "Enter new packet name:")
                if not name:
                    return
        else:
            # No packet selected or doesn't exist, create new
            name = tk.simpledialog.askstring("Save Packet", "Enter packet name:")
            if not name:
                return

        # Save packet data
        self.packets_data[name] = {
            "packet_type": self.pkt_type_var.get(),
            "description": self.desc_var.get(),
            "buffers": [
                {"method": m.get(), "value": v.get(), "hint": h.get()}
                for _, m, v, h in self.buffer_rows
            ]
        }
        self.save_packets_data()
        self.saved_pkt_menu['values'] = list(self.packets_data.keys())
        self.saved_pkt_var.set(name)  # Select the saved packet
        self.status_var.set(f"Packet '{name}' saved.")

    def load_packet(self):
        # open a selection dialog
        name = tk.simpledialog.askstring("Load Packet", "Enter packet name to load:")
        if not name or name not in self.packets_data:
            self.status_var.set(f"Packet '{name}' not found.")
            return
        self.load_packet_by_name(name)

    def load_selected_packet(self, event):
        name = self.saved_pkt_var.get()
        if name in self.packets_data:
            self.load_packet_by_name(name)

    def load_packet_by_name(self, name):
        data = self.packets_data[name]
        self.pkt_type_var.set(data.get("packet_type", "F5"))
        self.desc_var.set(data.get("description", ""))
        # Clear existing buffer rows
        for row, _, _, _ in self.buffer_rows:
            row.destroy()
        self.buffer_rows.clear()
        # Add loaded buffers with hints
        for buf in data.get("buffers", []):
            self.add_buffer_row(buf.get("method", ""), buf.get("value", ""), buf.get("hint", ""))
        self.status_var.set(f"Packet '{name}' loaded")


