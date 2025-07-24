import tkinter as tk
from tkinter import messagebox
import threading
import queue

from smb_core import SMBConnector, ShareEnumerator, RecursiveEnumerator
from gui_panels import ConnectionPanel, ProgressPanel, ResultsPanel
from utils import Logger
from models import ConnectionConfig

class SMBEnumeratorApp:
    def __init__(self, master):
        self.master = master
        master.title("SMB Enumerator")

        # Initialize frames
        self.connection_panel = ConnectionPanel(master, self.test_connection, self.start_enumeration)
        self.progress_panel = ProgressPanel(master)
        self.results_panel = ResultsPanel(master)

        # Pack frames
        self.connection_panel.frame.pack(fill=tk.X)
        self.progress_panel.status_label.pack(fill=tk.X)
        self.progress_panel.progress_bar.pack(fill=tk.X)
        self.progress_panel.stop_btn.pack(pady=5)
        self.results_panel.frame.pack(fill=tk.BOTH, expand=True)

        # Initialize logger
        # self.logger = Logger(self.results_panel.text)

        # Initialize queues for thread communication
        self.queue = queue.Queue()
        self.stop_event = threading.Event()

        # Bind start and stop buttons
        self.connection_panel.start_btn.config(command=self.start_enumeration)
        self.connection_panel.connect_btn.config(command=self.test_connection)
        self.connection_panel.start_btn.config(state=tk.NORMAL)
        self.connection_panel.connect_btn.config(state=tk.NORMAL)

        # Update method for processing queue
        self.master.after(100, self.process_queue)

    def start_enumeration(self):
        # Get parameters from connection panel
        domain = self.connection_panel.domain_var.get()
        dc_ip = self.connection_panel.dc_ip.get()
        username = self.connection_panel.username_var.get()
        password = self.connection_panel.password_var.get()
        depth = self.connection_panel.depth_var.get()

        # Validate inputs
        if not domain or not dc_ip or not username:
            messagebox.showerror("Input Error", "Domain, DC IP, and Username are required.")
            return

        # Disable start button and enable stop button
        self.connection_panel.start_btn.config(state=tk.DISABLED)
        # self.connection_panel.stop_button.config(state=tk.NORMAL)

        # Clear results text
        self.results_panel.clear()

        # Log the start of the enumeration
        # self.logger.log("Starting enumeration...")

        # Create and start the enumeration thread
        self.enumeration_thread = threading.Thread(target=self.enumerate_shares,
                                                  args=(domain, dc_ip, username, password, depth))
        self.enumeration_thread.start()

    def stop_enumeration(self):
        # Set the stop event
        self.stop_event.set()

        # Wait for the enumeration thread to finish
        self.enumeration_thread.join()

        # Disable stop button and enable start button
        # self.connection_panel.stop_button.config(state=tk.DISABLED)
        self.connection_panel.start_btn.config(state=tk.NORMAL)

        # Log the stop of the enumeration
        # self.logger.log("Enumeration stopped.")

    def enumerate_shares(self, domain, dc_ip, username, password, depth):
        # Here, just connect to the single DC IP provided
        try:
            smb = SMBConnector()
            config = ConnectionConfig(
                target=dc_ip,
                username=username,
                password=password,
                domain=domain
            )
            connected, msg = smb.connect(config)
            if not connected:
                # self.logger.log(f"Connection failed: {msg}")
                return
            # Enumerate shares using the depth parameter
            share_enum = ShareEnumerator(smb)
            shares, _ = share_enum.list_shares()
            for share in shares:
                # Recursively enumerate files/folders up to the specified depth
                rec_enum = RecursiveEnumerator(smb)
                results = rec_enum.enumerate_recursive(share.name, int(depth))
                for file_info in results:
                    self.queue.put(file_info)
        except Exception as e:
            # self.logger.log(f"Error enumerating shares: {e}")
            pass

    def ip_to_int(self, ip):
        # Convert an IP address from string to integer
        octets = map(int, ip.split('.'))
        return sum(octet << (8 * i) for i, octet in enumerate(reversed(list(octets))))

    def int_to_ip(self, ip_int):
        # Convert an IP address from integer to string
        return '.'.join(str((ip_int >> (8 * i)) & 0xFF) for i in range(4))[::-1]

    def process_queue(self):
        # Process the shares in the queue
        try:
            while True:
                # Get the share from the queue
                share = self.queue.get_nowait()

                # Here you can add code to process each share
                # For example, you can enumerate files in the share

                # Mark the share as processed
                self.queue.task_done()
        except queue.Empty:
            # No more shares in the queue
            pass

        # Schedule the next queue processing
        self.master.after(100, self.process_queue)

    def test_connection(self):
        # Gather parameters from the GUI
        domain = self.connection_panel.domain_var.get()
        dc_ip = self.connection_panel.dc_ip.get()
        username = self.connection_panel.username_var.get()
        password = self.connection_panel.password_var.get()

        # Validate inputs
        if not domain or not dc_ip or not username:
            messagebox.showerror("Input Error", "Domain, DC IP, and Username are required.")
            return

        # Attempt to connect
        smb = SMBConnector()
        config = ConnectionConfig(
            target=dc_ip,
            username=username,
            password=password,
            domain=domain
        )
        connected, msg = smb.connect(config)
        if connected:
            messagebox.showinfo("Connection Test", "Connection successful!")
        else:
            messagebox.showerror("Connection Test", f"Connection failed: {msg}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SMBEnumeratorApp(root)
    root.mainloop()