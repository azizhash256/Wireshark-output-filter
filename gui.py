#!/usr/bin/env python3
"""
TraceScout GUI — drag & drop front-end for ip_inspector.py
- Pick a capture/export file
- Toggle Reverse DNS / RDAP / Packet limit
- View a sortable table, save CSV/JSON
"""
import os
import json
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from subprocess import Popen, PIPE
from pathlib import Path

from tracescout_core import run_tracescout  # our in-proc runner (see tracescout_core.py)

OUT_DIR = "out"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("TraceScout — IP Extractor")
        self.geometry("900x560")
        self.resizable(True, True)

        self.path_var = tk.StringVar()
        self.reverse_dns = tk.BooleanVar(value=False)
        self.rdap = tk.BooleanVar(value=False)
        self.limit_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Ready.")

        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Input:").pack(side=tk.LEFT, padx=(0,6))
        entry = ttk.Entry(top, textvariable=self.path_var)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(top, text="Browse…", command=self.browse).pack(side=tk.LEFT, padx=6)

        opts = ttk.Frame(self, padding=(8,0))
        opts.pack(fill=tk.X)
        ttk.Checkbutton(opts, text="Reverse DNS", variable=self.reverse_dns).pack(side=tk.LEFT)
        ttk.Checkbutton(opts, text="RDAP (ASN/Org)", variable=self.rdap).pack(side=tk.LEFT, padx=(12,0))
        ttk.Label(opts, text="Packet limit (PCAP):").pack(side=tk.LEFT, padx=(12,4))
        ttk.Entry(opts, width=8, textvariable=self.limit_var).pack(side=tk.LEFT)

        btns = ttk.Frame(self, padding=8)
        btns.pack(fill=tk.X)
        ttk.Button(btns, text="Run", command=self.run).pack(side=tk.LEFT)
        ttk.Button(btns, text="Save CSV/JSON", command=self.save_outputs).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Clear Table", command=self.clear_table).pack(side=tk.LEFT, padx=6)

        # table
        self.tree = ttk.Treeview(self, columns=("ip","v","domains","providers","sites","rdns","rdap"), show="headings")
        for col, w in [("ip",160),("v",30),("domains",240),("providers",140),("sites",160),("rdns",220),("rdap",260)]:
            self.tree.heading(col, text=col.upper(), command=lambda c=col: self._sort_by(c, False))
            self.tree.column(col, width=w, anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        status = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status.pack(fill=tk.X, side=tk.BOTTOM)

        # DnD (basic)
        self.drop_target_register("*")
        self.dnd_bind("<<Drop>>", self._on_drop)

    def browse(self):
        p = filedialog.askopenfilename(title="Select capture or export",
                                       filetypes=[("All","*.*"),("PCAP","*.pcap *.pcapng"),("Text","*.txt *.log *.csv *.json")])
        if p:
            self.path_var.set(p)

    def _on_drop(self, event):
        path = event.data.strip().strip("{}")
        if os.path.exists(path):
            self.path_var.set(path)

    def clear_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

    def _sort_by(self, col, desc):
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        try:
            data.sort(key=lambda t: (t[0] is None, t[0]))
        except Exception:
            pass
        if desc:
            data.reverse()
        for index, item in enumerate(data):
            self.tree.move(item[1], "", index)
        self.tree.heading(col, command=lambda: self._sort_by(col, not desc))

    def run(self):
        path = self.path_var.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showwarning("Input", "Please choose a valid file.")
            return

        limit = None
        if self.limit_var.get().strip():
            try:
                limit = int(self.limit_var.get().strip())
            except ValueError:
                messagebox.showwarning("Limit", "Packet limit must be an integer.")
                return

        self.status_var.set("Running…")
        self.clear_table()

        def worker():
            try:
                records = run_tracescout(
                    input_path=path,
                    known="config/known_providers.yml" if os.path.exists("config/known_providers.yml") else None,
                    sites="config/known_sites.yml" if os.path.exists("config/known_sites.yml") else None,
                    reverse_dns=self.reverse_dns.get(),
                    rdap=self.rdap.get(),
                    limit=limit,
                    cache_ttl=86400,   # 24h cache by default
                )
                for r in records:
                    rdap_parts = []
                    if isinstance(r.get("rdap"), dict):
                        if r["rdap"].get("asn"):
                            rdap_parts.append(f"ASN {r['rdap']['asn']}")
                        if r["rdap"].get("asn_description"):
                            rdap_parts.append(r["rdap"]["asn_description"])
                        if r["rdap"].get("network"):
                            rdap_parts.append(r["rdap"]["network"])
                    self.tree.insert("", tk.END, values=(
                        r["ip"], r["version"],
                        ", ".join(r["domains"]),
                        ", ".join(r["known_providers"]),
                        ", ".join(r["known_sites"]),
                        r.get("rDNS") or "",
                        " | ".join(rdap_parts)
                    ))
                self.status_var.set(f"Done. {len(records)} unique IP(s).")
            except Exception as e:
                self.status_var.set("Error.")
                messagebox.showerror("Run failed", str(e))

        threading.Thread(target=worker, daemon=True).start()

    def save_outputs(self):
        if not self.tree.get_children():
            messagebox.showinfo("Save", "Nothing to save. Run first.")
            return
        os.makedirs(OUT_DIR, exist_ok=True)
        # Pull table back into a simple list of records
        cols = ["ip","version","domains","known_providers","known_sites","rDNS","rdap"]
        records = []
        for iid in self.tree.get_children():
            v = self.tree.item(iid)["values"]
            records.append({
                "ip": v[0],
                "version": int(v[1]),
                "domains": [d.strip() for d in str(v[2]).split(",") if d.strip()],
                "known_providers": [d.strip() for d in str(v[3]).split(",") if d.strip()],
                "known_sites": [d.strip() for d in str(v[4]).split(",") if d.strip()],
                "rDNS": v[5] or None,
                "rdap": v[6] or "",
            })
        with open(os.path.join(OUT_DIR, "gui_ips.json"), "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2)
        messagebox.showinfo("Saved", f"Saved {os.path.join(OUT_DIR,'gui_ips.json')}")

if __name__ == "__main__":
    App().mainloop()
