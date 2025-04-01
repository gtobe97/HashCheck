import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import hashlib
import subprocess
import os
import platform
import webbrowser
from datetime import datetime
import json
import ctypes

ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("HashCheck.FileHasher")


class FileHashCalculator:
    def __init__(self, root):
        self.root = root
        self.root.title("Hash Check")
        self.root.geometry("800x550")
        self.root.resizable(True, True)
        
        # Set app icon
        try:
            if platform.system() == "Windows":
                self.root.iconbitmap(default="hashcheck.ico")
            else:
                icon = tk.PhotoImage(file="hashcheck.ico")
                self.root.iconphoto(True, icon)
        except:
            pass
            
        # Theme colors
        self.theme = {
            "bg": "#F5F5F5",
            "fg": "#333333",
            "accent": "#2196F3",
            "hover": "#42A5F5",
            "secondary_bg": "#FFFFFF",
            "border": "#E0E0E0"
        }
        
        # Set style
        self.style = ttk.Style()
        
        # Load history from file
        self.history_file = os.path.join(os.path.expanduser("~"), "file_hash_history.json")
        self.load_history()
        
        self.create_widgets()
        self.apply_theme()
    
    def create_widgets(self):
        # Main frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Top bar
        self.top_bar = ttk.Frame(self.main_frame)
        self.top_bar.pack(fill="x", pady=(0, 10))
        
        # App title
        self.app_title = ttk.Label(
            self.top_bar, 
            text="Hash Check", 
            font=("Helvetica", 16, "bold")
        )
        self.app_title.pack(side="left", padx=5)
        
        # Frame for file selection area with fancy border
        self.file_frame = ttk.LabelFrame(self.main_frame, text="File Selection")
        self.file_frame.pack(fill="x", pady=10, ipady=10)
        
        # File selection area
        self.file_info_frame = ttk.Frame(self.file_frame)
        self.file_info_frame.pack(fill="x", padx=20, pady=10)
        
        # Label for instruction
        self.instruction_label = ttk.Label(
            self.file_info_frame, 
            text="Select a file to calculate its SHA256 hash",
            anchor="center",
            font=("Helvetica", 10)
        )
        self.instruction_label.pack(pady=5)
        
        # File path frame
        self.file_path_frame = ttk.Frame(self.file_info_frame)
        self.file_path_frame.pack(fill="x", pady=5)
        
        self.file_path_entry = ttk.Entry(self.file_path_frame, width=70)
        self.file_path_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        # Button to browse files with improved styling
        self.browse_button = ttk.Button(
            self.file_path_frame,
            text="Browse",
            command=self.browse_file
        )
        self.browse_button.pack(side="right")
        
        # Results section
        self.results_frame = ttk.LabelFrame(self.main_frame, text="Hash Result")
        self.results_frame.pack(fill="x", pady=10)
        
        # Hash result
        self.hash_frame = ttk.Frame(self.results_frame)
        self.hash_frame.pack(fill="x", padx=10, pady=10)
        
        self.hash_result = ttk.Entry(self.hash_frame, font=("Consolas", 10))
        self.hash_result.pack(side="left", fill="x", expand=True, padx=(5, 10))
        
        # Button row in results frame
        self.action_frame = ttk.Frame(self.results_frame)
        self.action_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        # Copy button
        self.copy_button = ttk.Button(
            self.action_frame, 
            text="Copy", 
            command=self.copy_to_clipboard
        )
        self.copy_button.pack(side="left", padx=5)
        self.copy_button["state"] = "disabled"
        
        # VirusTotal button
        self.vt_button = ttk.Button(
            self.action_frame, 
            text="Search on VirusTotal", 
            command=self.search_virustotal
        )
        self.vt_button.pack(side="left", padx=5)
        self.vt_button["state"] = "disabled"
        
        # Calculate button
        self.calculate_button = ttk.Button(
            self.action_frame,
            text="Calculate",
            command=self.calculate_from_path
        )
        self.calculate_button.pack(side="right", padx=5)
        
        # History section
        self.history_frame = ttk.LabelFrame(self.main_frame, text="History")
        self.history_frame.pack(fill="both", expand=True, pady=10)
        
        # Sort options and controls
        self.history_controls = ttk.Frame(self.history_frame)
        self.history_controls.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(self.history_controls, text="Sort by:").pack(side="left", padx=(0, 5))
        
        self.sort_var = tk.StringVar(value="date")
        ttk.Radiobutton(
            self.history_controls, 
            text="Date", 
            variable=self.sort_var, 
            value="date", 
            command=self.update_history_display
        ).pack(side="left", padx=5)
        
        ttk.Radiobutton(
            self.history_controls, 
            text="Name", 
            variable=self.sort_var, 
            value="name", 
            command=self.update_history_display
        ).pack(side="left", padx=5)
        
        # Search in history
        self.search_frame = ttk.Frame(self.history_controls)
        self.search_frame.pack(side="right", padx=5)
        
        ttk.Label(self.search_frame, text="Search:").pack(side="left", padx=(0, 5))
        
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda name, index, mode: self.update_history_display())
        self.search_entry = ttk.Entry(self.search_frame, textvariable=self.search_var, width=20)
        self.search_entry.pack(side="left", padx=5)
        
        # Clear history button
        self.clear_button = ttk.Button(
            self.history_controls, 
            text="Clear History", 
            command=self.clear_history
        )
        self.clear_button.pack(side="right", padx=5)
        
        # History list with scrollbar
        self.history_tree_frame = ttk.Frame(self.history_frame)
        self.history_tree_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.history_tree = ttk.Treeview(
            self.history_tree_frame, 
            columns=("Filename", "Hash", "Date"),
            show="headings",
            selectmode="browse"
        )
        self.history_tree.heading("Filename", text="Filename")
        self.history_tree.heading("Hash", text="SHA256 Hash")
        self.history_tree.heading("Date", text="Date & Time")
        
        self.history_tree.column("Filename", width=200)
        self.history_tree.column("Hash", width=400)
        self.history_tree.column("Date", width=150)
        
        # Create vertical scrollbar
        scrollbar_y = ttk.Scrollbar(self.history_tree_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar_y.set)
        
        # Create horizontal scrollbar
        scrollbar_x = ttk.Scrollbar(self.history_tree_frame, orient="horizontal", command=self.history_tree.xview)
        self.history_tree.configure(xscrollcommand=scrollbar_x.set)
        
        # Pack the tree and scrollbars
        self.history_tree.pack(side="left", fill="both", expand=True)
        scrollbar_y.pack(side="right", fill="y")
        scrollbar_x.pack(side="bottom", fill="x")
        
        # Bind double-click event to copy hash
        self.history_tree.bind("<Double-1>", self.on_history_item_double_click)
        
        # Status bar at the bottom
        self.status_bar = ttk.Label(
            self.root, 
            text="Ready", 
            relief="sunken", 
            anchor="w"
        )
        self.status_bar.pack(side="bottom", fill="x")
        
        # Update the history display
        self.update_history_display()
    
    def apply_theme(self):
        """Apply the theme to all widgets"""
        # Configure ttk styles
        self.style.configure("TFrame", background=self.theme["bg"])
        self.style.configure("TLabel", background=self.theme["bg"], foreground=self.theme["fg"])
        self.style.configure("TLabelframe", background=self.theme["bg"], foreground=self.theme["fg"])
        self.style.configure("TLabelframe.Label", background=self.theme["bg"], foreground=self.theme["fg"])
        self.style.configure("TButton", background=self.theme["accent"], foreground=self.theme["fg"])
        self.style.map("TButton", 
                       background=[("active", self.theme["hover"])],
                       foreground=[("active", self.theme["fg"])])
        self.style.configure("TEntry", fieldbackground=self.theme["secondary_bg"], foreground=self.theme["fg"])
        self.style.configure("TCheckbutton", background=self.theme["bg"], foreground=self.theme["fg"])
        self.style.configure("TRadiobutton", background=self.theme["bg"], foreground=self.theme["fg"])

        # Configure Treeview
        self.style.configure("Treeview", 
                            background=self.theme["secondary_bg"],
                            foreground=self.theme["fg"],
                            fieldbackground=self.theme["secondary_bg"])
        self.style.map("Treeview",
                      background=[("selected", self.theme["accent"])],
                      foreground=[("selected", "#FFFFFF")])
        
        # Configure the root window
        self.root.configure(background=self.theme["bg"])
        self.status_bar.configure(background=self.theme["secondary_bg"], foreground=self.theme["fg"])
    
    def browse_file(self):
        """Open file dialog to select a file"""
        file_path = filedialog.askopenfilename(title="Select a file to calculate SHA256 hash")
        if file_path:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, file_path)
            self.process_file(file_path)
    
    def calculate_from_path(self):
        """Calculate hash from the path in the entry field"""
        file_path = self.file_path_entry.get().strip()
        if file_path and os.path.isfile(file_path):
            self.process_file(file_path)
        else:
            messagebox.showwarning("Invalid Path", "Please enter a valid file path.")
    
    def process_file(self, file_path):
        """Process the selected file and calculate its hash"""
        try:
            # Update the status bar
            self.status_bar.config(text=f"Calculating hash for: {os.path.basename(file_path)}...")
            self.root.update()
            
            # Calculate hash
            hash_value = self.calculate_hash(file_path)
            
            # Update the result entry
            self.hash_result.delete(0, tk.END)
            self.hash_result.insert(0, hash_value)
            self.copy_button["state"] = "normal"
            self.vt_button["state"] = "normal"
            
            # Update the status
            self.status_bar.config(text=f"SHA256 hash calculated for: {os.path.basename(file_path)}")
            
            # Add to history
            self.add_to_history(os.path.basename(file_path), hash_value)
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.status_bar.config(text="Error calculating hash")
    
    def calculate_hash(self, file_path):
        """Calculate SHA256 hash of the file"""
        if platform.system() == 'Windows':
            # Use PowerShell on Windows
            try:
                result = subprocess.run(
                    ['powershell', '-Command', f"(Get-FileHash -Algorithm SHA256 -Path '{file_path}').Hash"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                return result.stdout.strip()
            except subprocess.CalledProcessError:
                # Fallback to Python implementation
                return self.calculate_hash_python(file_path)
        else:
            # Use Python implementation for non-Windows platforms
            return self.calculate_hash_python(file_path)
    
    def calculate_hash_python(self, file_path):
        """Calculate SHA256 hash using Python's hashlib"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read and update hash in chunks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest().upper()
    
    def copy_to_clipboard(self):
        """Copy the hash result to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.hash_result.get())
        self.status_bar.config(text="Hash copied to clipboard!")
    
    def search_virustotal(self):
        """Open VirusTotal website with the hash for searching"""
        hash_value = self.hash_result.get()
        if hash_value:
            vt_url = f"https://www.virustotal.com/gui/search/{hash_value}"
            webbrowser.open(vt_url)
            self.status_bar.config(text="Opened VirusTotal search in browser")
        else:
            messagebox.showwarning("Warning", "No hash to search. Please calculate a file hash first.")
    
    def load_history(self):
        """Load hash history from file"""
        self.history = []
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    self.history = json.load(f)
        except Exception as e:
            print(f"Error loading history: {str(e)}")
            self.status_bar.config(text="Error loading history file")
    
    def save_history(self):
        """Save hash history to file"""
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            print(f"Error saving history: {str(e)}")
            self.status_bar.config(text="Error saving history file")
    
    def add_to_history(self, filename, hash_value):
        """Add a new entry to history"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Check if this hash already exists in history
        for item in self.history:
            if item['hash'] == hash_value:
                # If it exists, update the timestamp
                item['date'] = timestamp
                self.save_history()
                self.update_history_display()
                return
        
        # If not found, add new entry
        entry = {
            'filename': filename,
            'hash': hash_value,
            'date': timestamp
        }
        self.history.append(entry)
        self.save_history()
        self.update_history_display()
    
    def update_history_display(self):
        """Update the history treeview with sorted and filtered entries"""
        # Clear the treeview
        for i in self.history_tree.get_children():
            self.history_tree.delete(i)
        
        # Get search filter
        search_term = self.search_var.get().lower()
        
        # Filter history
        filtered_history = []
        for item in self.history:
            if (search_term in item['filename'].lower() or 
                search_term in item['hash'].lower()):
                filtered_history.append(item)
        
        # Sort history
        sort_by = self.sort_var.get()
        if sort_by == "date":
            sorted_history = sorted(filtered_history, key=lambda x: x['date'], reverse=True)
        else:  # sort by name
            sorted_history = sorted(filtered_history, key=lambda x: x['filename'].lower())
        
        # Insert sorted history items
        for item in sorted_history:
            self.history_tree.insert("", "end", values=(
                item['filename'],
                item['hash'],
                item['date']
            ))
        
        # Update status bar
        if len(filtered_history) != len(self.history):
            self.status_bar.config(text=f"Showing {len(filtered_history)} of {len(self.history)} history items")
        else:
            self.status_bar.config(text=f"Showing {len(self.history)} history items")
    
    def clear_history(self):
        """Clear all history entries"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all history?"):
            self.history = []
            self.save_history()
            self.update_history_display()
            self.status_bar.config(text="History cleared")
    
    def on_history_item_double_click(self, event):
        """Handle double-click on history item to copy hash"""
        selected_item = self.history_tree.selection()
        if selected_item:
            item_values = self.history_tree.item(selected_item)['values']
            if len(item_values) >= 2:  # Make sure we have hash value
                hash_value = item_values[1]
                self.hash_result.delete(0, tk.END)
                self.hash_result.insert(0, hash_value)
                self.copy_button["state"] = "normal"
                self.vt_button["state"] = "normal"
                self.copy_to_clipboard()

def main():
    root = tk.Tk()
    app = FileHashCalculator(root)
    root.mainloop()

if __name__ == "__main__":
    main()
