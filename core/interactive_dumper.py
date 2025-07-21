#!/usr/bin/env python3
"""
Interactive PE Dumper - GUI based executable analysis tool
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import customtkinter as ctk
import subprocess
import os
import sys
import threading
import time
from pathlib import Path
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.main import PEDumper
from datetime import datetime

class InteractiveDumper:
    def __init__(self):
        # Set the appearance mode and color theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Create main window
        self.root = ctk.CTk()
        self.root.title("PE Dumper Interactive - v2.0")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Variables
        self.selected_exe = tk.StringVar()
        self.output_path = tk.StringVar(value=os.path.join(os.path.expanduser("~"), "Desktop"))
        self.target_process = None
        self.dumper = None
        self.auth_key = tk.StringVar()
        
        # Set default output path
        self.output_path.set(os.path.join(os.path.expanduser("~"), "Desktop", "DumperOutput"))
        
        self.create_interface()
        
    def create_interface(self):
        """Create the main GUI interface"""
        
        # Title
        title_label = ctk.CTkLabel(
            self.root, 
            text="🔍 PE Dumper Interactive", 
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(pady=20)
        
        # Main container
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # File Selection Section
        file_section = ctk.CTkFrame(main_frame)
        file_section.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(file_section, text="📁 File Selection", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Executable selection
        exe_frame = ctk.CTkFrame(file_section)
        exe_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(exe_frame, text="Target Executable:").pack(side="left", padx=5)
        self.exe_entry = ctk.CTkEntry(exe_frame, textvariable=self.selected_exe, width=400)
        self.exe_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        ctk.CTkButton(exe_frame, text="Browse", command=self.browse_exe, width=100).pack(side="right", padx=5)
        
        # Output path selection
        output_frame = ctk.CTkFrame(file_section)
        output_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(output_frame, text="Output Directory:").pack(side="left", padx=5)
        self.output_entry = ctk.CTkEntry(output_frame, textvariable=self.output_path, width=400)
        self.output_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        ctk.CTkButton(output_frame, text="Browse", command=self.browse_output, width=100).pack(side="right", padx=5)
        
        # Control Section
        control_section = ctk.CTkFrame(main_frame)
        control_section.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(control_section, text="🎮 Process Control", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Step 1: Launch executable
        step1_frame = ctk.CTkFrame(control_section)
        step1_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(step1_frame, text="Step 1:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=5)
        self.launch_btn = ctk.CTkButton(step1_frame, text="🚀 Launch Target Executable", command=self.launch_executable, width=200)
        self.launch_btn.pack(side="left", padx=10)
        
        self.process_status = ctk.CTkLabel(step1_frame, text="⭕ Not Running")
        self.process_status.pack(side="left", padx=10)
        
        # Step 2: Key input
        step2_frame = ctk.CTkFrame(control_section)
        step2_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(step2_frame, text="Step 2:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=5)
        ctk.CTkLabel(step2_frame, text="Authentication Key:").pack(side="left", padx=5)
        
        self.key_entry = ctk.CTkEntry(step2_frame, textvariable=self.auth_key, placeholder_text="Enter your key here...", width=200)
        self.key_entry.pack(side="left", padx=5)
        
        # Step 3: Trigger dump
        step3_frame = ctk.CTkFrame(control_section)
        step3_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(step3_frame, text="Step 3:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=5)
        self.dump_btn = ctk.CTkButton(
            step3_frame, 
            text="🔓 Key Unlocked - Start Dumping", 
            command=self.start_dumping, 
            width=250,
            state="disabled"
        )
        self.dump_btn.pack(side="left", padx=10)
        
        self.dump_status = ctk.CTkLabel(step3_frame, text="⭕ Waiting...")
        self.dump_status.pack(side="left", padx=10)
        
        # Progress Section
        progress_section = ctk.CTkFrame(main_frame)
        progress_section.pack(fill="both", expand=True, padx=20, pady=10)
        
        ctk.CTkLabel(progress_section, text="📊 Progress & Logs", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Progress bar
        self.progress = ctk.CTkProgressBar(progress_section)
        self.progress.pack(fill="x", padx=10, pady=5)
        self.progress.set(0)
        
        # Log area
        self.log_area = scrolledtext.ScrolledText(
            progress_section, 
            height=15, 
            bg="#2b2b2b", 
            fg="#ffffff", 
            font=("Consolas", 10)
        )
        self.log_area.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Status bar
        self.status_bar = ctk.CTkLabel(self.root, text="Ready to start...")
        self.status_bar.pack(side="bottom", fill="x", padx=5, pady=5)
        
    def log(self, message, level="INFO"):
        """Add message to log area"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color_prefix = ""
        
        if level == "ERROR":
            color_prefix = "❌"
        elif level == "SUCCESS":
            color_prefix = "✅"
        elif level == "WARNING":
            color_prefix = "⚠️"
        else:
            color_prefix = "ℹ️"
            
        log_message = f"[{timestamp}] {color_prefix} {message}\n"
        
        self.log_area.insert(tk.END, log_message)
        self.log_area.see(tk.END)
        self.root.update()
        
    def update_status(self, message):
        """Update status bar"""
        self.status_bar.configure(text=message)
        self.root.update()
        
    def browse_exe(self):
        """Browse for executable file"""
        file_path = filedialog.askopenfilename(
            title="Select Target Executable",
            filetypes=[
                ("Executable files", "*.exe"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.selected_exe.set(file_path)
            self.log(f"Selected executable: {os.path.basename(file_path)}")
            
    def browse_output(self):
        """Browse for output directory"""
        dir_path = filedialog.askdirectory(title="Select Output Directory")
        if dir_path:
            self.output_path.set(dir_path)
            self.log(f"Output directory set: {dir_path}")
            
    def launch_executable(self):
        """Launch the target executable"""
        if not self.selected_exe.get():
            messagebox.showerror("Error", "Please select an executable file first!")
            return
            
        if not os.path.exists(self.selected_exe.get()):
            messagebox.showerror("Error", "Selected executable file does not exist!")
            return
            
        try:
            self.log("Launching target executable...")
            self.update_status("Launching executable...")
            
            # Launch the executable
            self.target_process = subprocess.Popen([self.selected_exe.get()])
            
            self.process_status.configure(text="✅ Running")
            self.launch_btn.configure(state="disabled")
            self.dump_btn.configure(state="normal")
            
            self.log(f"Executable launched successfully! PID: {self.target_process.pid}", "SUCCESS")
            self.update_status("Executable is running. Enter your key and click 'Key Unlocked'")
            
            # Monitor process
            self.monitor_process()
            
        except Exception as e:
            self.log(f"Failed to launch executable: {e}", "ERROR")
            messagebox.showerror("Launch Error", f"Failed to launch executable:\n{e}")
            
    def monitor_process(self):
        """Monitor the launched process"""
        def check_process():
            while self.target_process and self.target_process.poll() is None:
                time.sleep(1)
                
            # Process ended
            if self.target_process:
                self.log("Target process has ended", "WARNING")
                self.process_status.configure(text="⭕ Process Ended")
                self.launch_btn.configure(state="normal")
                self.dump_btn.configure(state="disabled")
                self.update_status("Process ended. You can launch it again if needed.")
                
        thread = threading.Thread(target=check_process, daemon=True)
        thread.start()
        
    def start_dumping(self):
        """Start the dumping process"""
        if not self.auth_key.get():
            messagebox.showwarning("Warning", "Please enter the authentication key first!")
            return
            
        if not self.target_process or self.target_process.poll() is not None:
            messagebox.showerror("Error", "Target process is not running!")
            return
            
        # Run dumping in separate thread
        thread = threading.Thread(target=self.run_dumping, daemon=True)
        thread.start()
        
    def run_dumping(self):
        """Run the actual dumping process"""
        try:
            self.log("🔓 Authentication key received, starting dump process...", "SUCCESS")
            self.update_status("Dumping in progress...")
            self.progress.set(0.1)
            
            # Create output directory
            output_dir = self.output_path.get()
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                
            self.log(f"Output directory: {output_dir}")
            self.progress.set(0.2)
            
            # Initialize dumper
            self.dumper = PEDumper(
                exe_path=self.selected_exe.get(),
                verbose=True,
                auto_run=False,
                auto_cleanup=False
            )
            
            # Override output directory
            self.dumper.desktop_path = output_dir
            
            self.log("Initializing PE Dumper...")
            self.progress.set(0.3)
            
            # Validate and load PE
            if not self.dumper.validate_exe():
                self.log("PE validation failed!", "ERROR")
                return
                
            self.progress.set(0.4)
            
            if not self.dumper.load_pe():
                self.log("PE loading failed!", "ERROR")
                return
                
            self.progress.set(0.5)
            
            # Check authentication
            self.log("Analyzing authentication mechanisms...")
            has_auth, auth_strings = self.dumper.check_auth_mechanisms()
            
            if has_auth:
                self.log(f"Auth system detected: {', '.join(auth_strings)}")
                # Simulate key verification with provided key
                if self.dumper.verify_key(self.auth_key.get()):
                    self.log(f"Authentication successful with key: {self.auth_key.get()}", "SUCCESS")
                else:
                    self.log("Authentication failed, attempting bypass...", "WARNING")
                    if not self.dumper.attempt_auth_bypass():
                        self.log("All authentication methods failed!", "ERROR")
                        return
                        
            self.progress.set(0.7)
            
            # Create output directory for extraction
            if not self.dumper.create_output_directory():
                self.log("Failed to create extraction directory!", "ERROR")
                return
                
            self.progress.set(0.8)
            
            # Extract resources
            self.log("Starting resource extraction...")
            if not self.dumper.extract_resources():
                self.log("Resource extraction failed!", "ERROR")
                return
                
            self.progress.set(0.9)
            
            # Generate security report
            self.dumper.generate_security_report()
            
            self.progress.set(1.0)
            
            self.log("🎉 Dumping completed successfully!", "SUCCESS")
            self.log(f"📁 Output directory: {self.dumper.output_dir}")
            self.log(f"📊 Security report: {os.path.join(self.dumper.output_dir, 'security_assessment_report.txt')}")
            
            self.update_status("Dumping completed successfully!")
            
            # Show completion message
            result = messagebox.askyesno(
                "Dumping Complete", 
                f"PE dumping completed successfully!\n\nOutput directory: {self.dumper.output_dir}\n\nWould you like to open the output directory?"
            )
            
            if result:
                self.open_output_directory()
                
            # Reset for next operation
            self.reset_interface()
            
        except Exception as e:
            self.log(f"Dumping error: {e}", "ERROR")
            messagebox.showerror("Dumping Error", f"An error occurred during dumping:\n{e}")
            self.update_status("Dumping failed!")
            
    def open_output_directory(self):
        """Open the output directory in file manager"""
        try:
            if self.dumper and self.dumper.output_dir:
                if sys.platform == "win32":
                    os.startfile(self.dumper.output_dir)
                elif sys.platform == "darwin":
                    subprocess.run(["open", self.dumper.output_dir])
                else:
                    subprocess.run(["xdg-open", self.dumper.output_dir])
        except Exception as e:
            self.log(f"Failed to open directory: {e}", "ERROR")
            
    def reset_interface(self):
        """Reset interface for next operation"""
        self.dump_btn.configure(state="disabled")
        self.launch_btn.configure(state="normal")
        self.auth_key.set("")
        self.progress.set(0)
        
    def run(self):
        """Start the application"""
        self.log("PE Dumper Interactive v2.0 started", "SUCCESS")
        self.log("Select an executable, launch it, enter your key, then start dumping!")
        self.root.mainloop()

def main():
    app = InteractiveDumper()
    app.run()

if __name__ == "__main__":
    main()