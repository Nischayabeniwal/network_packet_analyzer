from tkinter import (
    Tk, Text, Button, Scrollbar, END, Entry, Label, Checkbutton, IntVar, filedialog,
    Toplevel, messagebox, Frame, StringVar
)
from tkinter.ttk import Treeview, Style
from analyzer import PacketAnalyzer

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        if self.tipwindow or not self.text:
            return
        x, y, _, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 25
        y = y + cy + self.widget.winfo_rooty() + 25
        self.tipwindow = tw = Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = Label(tw, text=self.text, background="#333", foreground="white", relief="solid", borderwidth=1, font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hide_tip(self, event=None):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()

class PacketAnalyzerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Network Packet Analyzer")
        master.geometry("950x600")
        master.minsize(900, 500)

        # Dark mode toggle
        self.dark_mode = IntVar(value=0)
        self.set_theme()

        # Top frame for controls
        top_frame = Frame(master)
        top_frame.pack(side='top', fill='x', padx=5, pady=5)

        self.filter_label = Label(top_frame, text="Filter (BPF syntax):")
        self.filter_label.pack(side='left')
        self.filter_entry = Entry(top_frame, width=30)
        self.filter_entry.pack(side='left', padx=5)

        # Add question mark icon with tooltip
        self.filter_help = Label(top_frame, text="?", fg="white", bg="#007acc", font=("Segoe UI", 10, "bold"), width=2, relief="ridge", cursor="question_arrow")
        self.filter_help.pack(side='left', padx=(0, 8))
        ToolTip(
            self.filter_help,
            "Packet Filter (BPF syntax):\n"
            "Use expressions like:\n"
            "  tcp            (only TCP packets)\n"
            "  udp            (only UDP packets)\n"
            "  port 80        (packets to/from port 80)\n"
            "  host 8.8.8.8   (packets to/from 8.8.8.8)\n"
            "Leave blank to capture all packets.\n"
            "This works like Wireshark/tcpdump filters."
        )

        self.start_button = Button(top_frame, text="Start", command=self.start_capture)
        self.start_button.pack(side='left', padx=2)
        ToolTip(self.start_button, "Start capturing packets")

        self.pause_button = Button(top_frame, text="Pause", command=self.pause_capture)
        self.pause_button.pack(side='left', padx=2)
        ToolTip(self.pause_button, "Pause capturing packets")

        self.resume_button = Button(top_frame, text="Resume", command=self.resume_capture)
        self.resume_button.pack(side='left', padx=2)
        ToolTip(self.resume_button, "Resume capturing packets")

        self.stop_button = Button(top_frame, text="Stop", command=self.stop_capture)
        self.stop_button.pack(side='left', padx=2)
        ToolTip(self.stop_button, "Stop capturing packets")

        self.export_txt_button = Button(top_frame, text="Export TXT", command=self.export_txt)
        self.export_txt_button.pack(side='left', padx=2)
        ToolTip(self.export_txt_button, "Export captured packets to TXT")

        self.export_csv_button = Button(top_frame, text="Export CSV", command=self.export_csv)
        self.export_csv_button.pack(side='left', padx=2)
        ToolTip(self.export_csv_button, "Export captured packets to CSV")

        self.autoscroll_var = IntVar(value=1)
        self.autoscroll_check = Checkbutton(top_frame, text="Auto-scroll", variable=self.autoscroll_var)
        self.autoscroll_check.pack(side='left', padx=10)
        ToolTip(self.autoscroll_check, "Scroll to latest packet automatically")

        self.dark_check = Checkbutton(top_frame, text="Dark mode", variable=self.dark_mode, command=self.set_theme)
        self.dark_check.pack(side='left', padx=10)
        ToolTip(self.dark_check, "Toggle dark mode")

        # Help icon with manual tooltip
        self.help_icon = Label(
            top_frame, text="🛈", fg="white", bg="#28a745", font=("Segoe UI", 11, "bold"),
            width=2, relief="ridge", cursor="question_arrow"
        )
        self.help_icon.pack(side='left', padx=(0, 8))
        ToolTip(
            self.help_icon,
            "Network Packet Analyzer Manual:\n"
            "\n"
            "• Start: Begin capturing packets (admin rights needed).\n"
            "• Pause/Resume: Temporarily halt/resume capture.\n"
            "• Stop: End capture session.\n"
            "• Export TXT/CSV: Save captured data.\n"
            "• Filter: Use BPF syntax (e.g., tcp, port 80, host 8.8.8.8).\n"
            "• Auto-scroll: Scrolls to latest packet automatically.\n"
            "• Dark mode: Toggle dark/light theme.\n"
            "• Double-click a row for detailed packet view.\n"
            "\n"
            "Tip: Leave filter blank to capture all packets.\n"
            "Use as admin for best results."
        )

        # Info frame for stats
        info_frame = Frame(master)
        info_frame.pack(side='top', fill='x', padx=5, pady=2)

        self.packet_count_label = Label(info_frame, text="Packets: 0")
        self.packet_count_label.pack(side='left', padx=5)

        self.protocol_count_label = Label(info_frame, text="TCP: 0 | UDP: 0 | ICMP: 0 | Other: 0")
        self.protocol_count_label.pack(side='left', padx=10)

        # Treeview frame
        tree_frame = Frame(master)
        tree_frame.pack(fill='both', expand=True, padx=5, pady=5)

        columns = ("No", "Proto", "Source", "SrcPort", "Dest", "DstPort")
        self.tree = Treeview(tree_frame, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, anchor='center', stretch=True)
        self.tree.column("No", width=60, anchor='center')
        self.tree.pack(side='left', fill='both', expand=True)
        self.tree.bind("<Double-1>", self.show_packet_details)

        # Scrollbar for Treeview
        tree_scroll = Scrollbar(tree_frame, command=self.tree.yview)
        tree_scroll.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=tree_scroll.set)

        # Status bar
        self.status_var = StringVar()
        self.status_var.set("Ready.")
        self.status_bar = Label(master, textvariable=self.status_var, anchor='w', relief='sunken')
        self.status_bar.pack(side='bottom', fill='x')

        self.captured_packets = []
        self.packet_analyzer = PacketAnalyzer(self.process_packet)

    def set_theme(self):
        style = Style()
        if self.dark_mode.get():
            self.master.configure(bg="#23272e")
            style.theme_use('clam')
            style.configure("Treeview", background="#23272e", foreground="white", fieldbackground="#23272e", rowheight=24)
            style.configure("Treeview.Heading", background="#23272e", foreground="#00bfff", font=('Segoe UI', 10, 'bold'))
            style.map("Treeview", background=[('selected', '#444')])
        else:
            self.master.configure(bg="SystemButtonFace")
            style.theme_use('default')
            style.configure("Treeview", background="white", foreground="black", fieldbackground="white", rowheight=24)
            style.configure("Treeview.Heading", background="SystemButtonFace", foreground="black", font=('Segoe UI', 10, 'bold'))
            style.map("Treeview", background=[('selected', '#cce6ff')])

    def start_capture(self):
        self.tree.delete(*self.tree.get_children())
        self.captured_packets.clear()
        filter_str = self.filter_entry.get()
        self.packet_analyzer.start_capture(filter_str=filter_str)
        self.update_packet_count()
        self.status_var.set("Capturing packets...")

    def stop_capture(self):
        self.packet_analyzer.stop_capture()
        self.status_var.set("Capture stopped.")

    def pause_capture(self):
        self.packet_analyzer.pause_capture()
        self.status_var.set("Capture paused.")

    def resume_capture(self):
        self.packet_analyzer.resume_capture()
        self.status_var.set("Capture resumed.")

    def process_packet(self, packet_info):
        self.captured_packets.append(packet_info)
        self.tree.insert("", END, values=(
            packet_info["no"], packet_info["proto"], packet_info["src"], packet_info["src_port"],
            packet_info["dst"], packet_info["dst_port"]
        ))
        self.update_packet_count()
        if self.autoscroll_var.get():
            self.tree.yview_moveto(1)
        self.status_var.set(f"Captured packet #{packet_info['no']}")

    def export_txt(self):
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if filename:
            self.packet_analyzer.export_txt(filename, self.captured_packets)
            messagebox.showinfo("Export", "Exported to TXT successfully.")
            self.status_var.set(f"Exported to {filename}")

    def export_csv(self):
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if filename:
            self.packet_analyzer.export_csv(filename, self.captured_packets)
            messagebox.showinfo("Export", "Exported to CSV successfully.")
            self.status_var.set(f"Exported to {filename}")

    def update_packet_count(self):
        self.packet_count_label.config(text=f"Packets: {self.packet_analyzer.packet_count}")
        pc = self.packet_analyzer.protocol_counts
        self.protocol_count_label.config(
            text=f"TCP: {pc['TCP']} | UDP: {pc['UDP']} | ICMP: {pc['ICMP']} | Other: {pc['Other']}"
        )

    def show_packet_details(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        idx = int(self.tree.item(selected[0])["values"][0]) - 1
        packet_info = self.captured_packets[idx]
        packet = packet_info["raw"]
        detail_win = Toplevel(self.master)
        detail_win.title(f"Packet #{packet_info['no']} Details")
        text = Text(detail_win, wrap='word', width=100, height=30, bg="#181c20" if self.dark_mode.get() else "white", fg="white" if self.dark_mode.get() else "black")
        text.pack(fill='both', expand=True)
        text.insert(END, f"Summary: {packet_info['summary']}\n\n")
        text.insert(END, f"Headers:\n{packet.show(dump=True)}\n")
        try:
            payload = bytes(packet.payload)
            text.insert(END, f"\nPayload (hex):\n{payload.hex()}\n")
        except Exception:
            text.insert(END, "\nNo payload.\n")
        text.config(state='disabled')

if __name__ == "__main__":
    root = Tk()
    gui = PacketAnalyzerGUI(root)
    root.mainloop()