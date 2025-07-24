import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from models import ConnectionConfig, FileInfo, ItemType
from utils import FileUtils
from typing import Tuple

class ConnectionPanel:
    """GUI panel for connection settings"""
    
    def __init__(self, parent, on_connect_callback, on_start_callback):
        self.parent = parent
        self.on_connect = on_connect_callback
        self.on_start = on_start_callback
        
        # Variables
        self.domain_var = tk.StringVar()
        self.dc_ip_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.depth_var = tk.StringVar(value="3")
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the connection panel UI"""
        # Main frame
        self.frame = ttk.LabelFrame(self.parent, text="Connection Settings", padding="10")

        # Domain
        ttk.Label(self.frame, text="Domain:").grid(
            row=0, column=0, sticky=tk.W, padx=(0, 5), pady=2
        )
        ttk.Entry(self.frame, textvariable=self.domain_var, width=30).grid(
            row=0, column=1, sticky=(tk.W, tk.E), pady=2
        )

        # DC IP Address
        ttk.Label(self.frame, text="DC IP Address:").grid(
            row=1, column=0, sticky=tk.W, padx=(0, 5), pady=2
        )
        ttk.Entry(self.frame, textvariable=self.dc_ip_var, width=30).grid(
            row=1, column=1, sticky=(tk.W, tk.E), pady=2
        )

        # Username
        ttk.Label(self.frame, text="Username:").grid(
            row=2, column=0, sticky=tk.W, padx=(0, 5), pady=2
        )
        ttk.Entry(self.frame, textvariable=self.username_var, width=30).grid(
            row=2, column=1, sticky=(tk.W, tk.E), pady=2
        )
        
        # Password
        ttk.Label(self.frame, text="Password:").grid(
            row=3, column=0, sticky=tk.W, padx=(0, 5), pady=2
        )
        ttk.Entry(self.frame, textvariable=self.password_var, show="*", width=30).grid(
            row=3, column=1, sticky=(tk.W, tk.E), pady=2
        )
        
        # Depth setting
        ttk.Label(self.frame, text="Max Depth (-l):").grid(
            row=4, column=0, sticky=tk.W, padx=(0, 5), pady=2
        )
        ttk.Spinbox(self.frame, from_=1, to=10, textvariable=self.depth_var, width=10).grid(
            row=4, column=1, sticky=tk.W, pady=2
        )
        
        # Buttons
        button_frame = ttk.Frame(self.frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=(10, 0))
        
        self.connect_btn = ttk.Button(button_frame, text="Test Connection", command=self.on_connect)
        self.connect_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.start_btn = ttk.Button(button_frame, text="Start Enumeration", command=self.on_start)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # Configure grid
        self.frame.columnconfigure(1, weight=1)
    
    def get_config(self) -> ConnectionConfig:
        """Get connection configuration from UI"""
        return ConnectionConfig(
            target=self.dc_ip_var.get().strip(),
            username=self.username_var.get().strip(),
            password=self.password_var.get(),
            domain=self.domain_var.get().strip()
        )
    
    def get_depth(self) -> int:
        """Get enumeration depth"""
        try:
            return int(self.depth_var.get())
        except ValueError:
            return 3
    
    def validate_input(self) -> tuple[bool, str]:
        """Validate user input"""
        config = self.get_config()
        
        if not config.target:
            return False, "Target domain/IP is required"
        
        if not config.username:
            return False, "Username is required"
        
        # Password is now optional, so no check here
        
        if self.get_depth() < 1 or self.get_depth() > 10:
            return False, "Depth must be between 1 and 10"
        
        return True, "Valid"

    @property
    def dc_ip(self):
        return self.dc_ip_var

class ProgressPanel:
    """GUI panel for progress indication"""
    
    def __init__(self, parent):
        self.parent = parent
        self.setup_ui()
    
    def setup_ui(self):
        """Setup progress panel UI"""
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(self.parent, textvariable=self.status_var)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(self.parent, mode='indeterminate')
        
        # Stop button
        self.stop_btn = ttk.Button(self.parent, text="Stop", state=tk.DISABLED)
    
    def set_status(self, status: str):
        """Set status text"""
        self.status_var.set(status)
    
    def start_progress(self):
        """Start progress bar animation"""
        self.progress_bar.start()
    
    def stop_progress(self):
        """Stop progress bar animation"""
        self.progress_bar.stop()
    
    def set_stop_callback(self, callback):
        """Set stop button callback"""
        self.stop_btn.config(command=callback)
    
    def enable_stop(self):
        """Enable stop button"""
        self.stop_btn.config(state=tk.NORMAL)
    
    def disable_stop(self):
        """Disable stop button"""
        self.stop_btn.config(state=tk.DISABLED)

class ResultsPanel:
    """GUI panel for displaying results"""
    
    def __init__(self, parent):
        self.parent = parent
        self.setup_ui()
    
    def setup_ui(self):
        """Setup results panel UI"""
        # Main frame
        self.frame = ttk.LabelFrame(self.parent, text="Enumeration Results", padding="5")
        
        # Treeview
        columns = ('Share', 'Path', 'Type', 'Size', 'Modified')
        self.tree = ttk.Treeview(self.frame, columns=columns, show='tree headings', height=15)
        
        # Configure columns
        self.tree.heading('#0', text='Name')
        self.tree.heading('Share', text='Share')
        self.tree.heading('Path', text='Path')
        self.tree.heading('Type', text='Type')
        self.tree.heading('Size', text='Size')
        self.tree.heading('Modified', text='Modified')
        
        self.tree.column('#0', width=250)
        self.tree.column('Share', width=100)
        self.tree.column('Path', width=200)
        self.tree.column('Type', width=80)
        self.tree.column('Size', width=100)
        self.tree.column('Modified', width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Configure grid weights
        self.frame.columnconfigure(0, weight=1)
        self.frame.rowconfigure(0, weight=1)
        
        # Export button
        self.export_btn = ttk.Button(self.frame, text="Export Results", command=self.export_results)
        self.export_btn.grid(row=1, column=0, pady=(5, 0), sticky=tk.W)
    
    def clear_results(self):
        """Clear all results from tree"""
        for item in self.tree.get_children():
            self.tree.delete(item)
    
    def add_result(self, file_info: FileInfo):
        """Add a single result to the tree"""
        # Format display values
        size_str = FileUtils.format_size(file_info.size) if file_info.size > 0 else "-"
        if file_info.item_type == ItemType.DIRECTORY and file_info.size == 0:
            size_str = "-"
        
        modified_str = FileUtils.format_datetime(file_info.modified)
        
        # Add indent based on depth
        name_with_indent = "  " * file_info.depth + file_info.name
        
        # Choose appropriate icon/styling based on type
        if file_info.item_type == ItemType.ERROR:
            name_with_indent = "❌ " + name_with_indent
        elif file_info.item_type == ItemType.ACCESS_DENIED:
            name_with_indent = "🔒 " + name_with_indent
        elif file_info.item_type == ItemType.DIRECTORY:
            name_with_indent = "📁 " + name_with_indent
        else:
            name_with_indent = "📄 " + name_with_indent
        
        self.tree.insert('', tk.END,
                        text=name_with_indent,
                        values=(file_info.share, file_info.path, 
                               file_info.item_type.value, size_str, modified_str))
    
    def get_results_count(self) -> int:
        """Get number of results"""
        return len(self.tree.get_children())
    
    def export_results(self):
        """Export results to JSON file"""
        if not self.tree.get_children():
            messagebox.showwarning("Warning", "No results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                results = []
                for item in self.tree.get_children():
                    values = self.tree.item(item)
                    results.append({
                        'name': values['text'].strip(),
                        'share': values['values'][0],
                        'path': values['values'][1],
                        'type': values['values'][2],
                        'size': values['values'][3],
                        'modified': values['values'][4]
                    })
                
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                
                messagebox.showinfo("Success", f"Results exported to {filename}")
                
            except Exception as e:
                messagebox.showerror("Export Error", str(e))