from tkinter import Tk, Frame, Label, Button, Text, Scrollbar, END
from analyzer import PacketAnalyzer

class PacketAnalyzerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Network Packet Analyzer")
        self.master.geometry("600x400")

        self.frame = Frame(self.master)
        self.frame.pack(pady=10)

        self.start_button = Button(self.frame, text="Start Capture", command=self.start_capture)
        self.start_button.grid(row=0, column=0, padx=10)

        self.stop_button = Button(self.frame, text="Stop Capture", command=self.stop_capture, state='disabled')
        self.stop_button.grid(row=0, column=1, padx=10)

        self.text_area = Text(self.master, wrap='word', height=15, width=70)
        self.text_area.pack(pady=10)

        self.scrollbar = Scrollbar(self.master, command=self.text_area.yview)
        self.scrollbar.pack(side='right', fill='y')
        self.text_area.config(yscrollcommand=self.scrollbar.set)

        self.packet_analyzer = PacketAnalyzer(self.update_display)

    def start_capture(self):
        self.packet_analyzer.start_capture()
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')

    def stop_capture(self):
        self.packet_analyzer.stop_capture()
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')

    def update_display(self, packet_info):
        self.text_area.insert(END, packet_info + "\n")
        self.text_area.see(END)

if __name__ == "__main__":
    root = Tk()
    gui = PacketAnalyzerGUI(root)
    root.mainloop()