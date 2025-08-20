import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os

# Pillow is an external dependency, so we handle the import gracefully
try:
    from PIL import Image, ImageTk
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

# Import the functions from our mapper script
from mapper import parse_nmap_xml, create_network_diagram, get_dns_servers, DIAGRAMS_AVAILABLE

class NetworkMapperGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Mapper")
        self.geometry("800x600")

        # Store data
        self.hosts = []
        self.dns_servers = []
        self.image_path = "network_map.png"

        # --- Main Layout ---
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Top Frame for Controls ---
        controls_frame = ttk.Frame(main_frame)
        controls_frame.pack(fill=tk.X, pady=5)

        self.filepath_label = ttk.Label(controls_frame, text="Nmap XML File:")
        self.filepath_label.pack(side=tk.LEFT, padx=(0, 5))

        self.filepath_entry = ttk.Entry(controls_frame, width=50)
        self.filepath_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)

        self.browse_button = ttk.Button(controls_frame, text="Browse...", command=self.browse_file)
        self.browse_button.pack(side=tk.LEFT, padx=5)

        self.load_button = ttk.Button(controls_frame, text="Load and Scan", command=self.load_and_scan)
        self.load_button.pack(side=tk.LEFT, padx=5)

        # --- Results Frame ---
        results_frame = ttk.Frame(main_frame)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        results_frame.columnconfigure(1, weight=1) # Diagram column
        results_frame.rowconfigure(0, weight=1) # Treeview row

        # --- Treeview for Hosts ---
        self.tree = self.create_treeview(results_frame)
        self.tree.grid(row=0, column=0, sticky="nsew")

        # --- Diagram and DNS Frame ---
        diagram_dns_frame = ttk.Frame(results_frame)
        diagram_dns_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        diagram_dns_frame.rowconfigure(1, weight=1)
        diagram_dns_frame.columnconfigure(0, weight=1)

        self.generate_diagram_button = ttk.Button(diagram_dns_frame, text="Generate Diagram", command=self.generate_diagram)
        self.generate_diagram_button.grid(row=0, column=0, pady=5, sticky="ew")

        self.image_label = ttk.Label(diagram_dns_frame, text="Diagram will be shown here.", anchor="center")
        self.image_label.grid(row=1, column=0, sticky="nsew")

        self.dns_label = ttk.Label(diagram_dns_frame, text="DNS Servers:", font=("", 10, "bold"))
        self.dns_label.grid(row=2, column=0, sticky="ew", pady=(10,0))
        self.dns_text = tk.Text(diagram_dns_frame, height=4, state="disabled", background=self.cget('bg'), relief="flat")
        self.dns_text.grid(row=3, column=0, sticky="ew")


        # --- Status Bar ---
        self.status_bar = ttk.Label(self, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def create_treeview(self, parent):
        """Creates and configures the Treeview widget for displaying hosts."""
        tree_frame = ttk.Frame(parent)

        tree = ttk.Treeview(tree_frame, columns=("IP", "Hostname"), show="headings")
        tree.heading("IP", text="IP Address")
        tree.heading("Hostname", text="Hostname")
        tree.column("IP", width=120)
        tree.column("Hostname", width=180)

        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        return tree

    def browse_file(self):
        """Opens a file dialog to select the Nmap XML file."""
        filepath = filedialog.askopenfilename(
            title="Select Nmap XML File",
            filetypes=[("XML Files", "*.xml"), ("All Files", "*.*")]
        )
        if filepath:
            self.filepath_entry.delete(0, tk.END)
            self.filepath_entry.insert(0, filepath)
            self.status_bar.config(text=f"Selected file: {os.path.basename(filepath)}")

    def load_and_scan(self):
        """Loads data from the XML file, parses it, and updates the GUI."""
        filepath = self.filepath_entry.get()
        if not os.path.exists(filepath):
            messagebox.showerror("Error", f"File not found: {filepath}")
            return

        self.status_bar.config(text="Parsing XML file...")
        self.update_idletasks()

        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.hosts = parse_nmap_xml(filepath)
        if not self.hosts:
            messagebox.showinfo("No Hosts Found", "Could not parse any host information from the file.")
            self.status_bar.config(text="Ready")
            return

        # Populate treeview
        for host in self.hosts:
            host_id = self.tree.insert("", tk.END, values=(host['ip'], host['hostname']))
            if host['ports']:
                for port in host['ports']:
                    service = port.get('product', port.get('service', 'unknown'))
                    self.tree.insert(host_id, tk.END, values=(f"  {port['portid']}/tcp", service))

        # Get and display DNS servers
        self.dns_servers = get_dns_servers()
        self.dns_text.config(state="normal")
        self.dns_text.delete("1.0", tk.END)
        if self.dns_servers:
            self.dns_text.insert(tk.END, "\n".join(self.dns_servers))
        else:
            self.dns_text.insert(tk.END, "No DNS servers found.")
        self.dns_text.config(state="disabled")

        self.status_bar.config(text=f"Successfully parsed {len(self.hosts)} hosts.")

    def generate_diagram(self):
        """Generates and displays the network diagram."""
        if not self.hosts:
            messagebox.showwarning("No Data", "Please load and scan a file first.")
            return

        if not DIAGRAMS_AVAILABLE:
            messagebox.showerror("Dependency Missing", "'diagrams' library not found. Cannot create diagram.")
            return

        if not PILLOW_AVAILABLE:
            messagebox.showerror("Dependency Missing", "'Pillow' library not found. Cannot display diagram.")
            return

        self.status_bar.config(text="Generating diagram...")
        self.update_idletasks()

        create_network_diagram(self.hosts, self.dns_servers, output_filename=os.path.splitext(self.image_path)[0])

        if os.path.exists(self.image_path):
            try:
                # Open and display the image
                img = Image.open(self.image_path)

                # Resize image to fit the label
                label_w = self.image_label.winfo_width()
                label_h = self.image_label.winfo_height()
                if label_w > 1 and label_h > 1: # check if the label has a size
                    img.thumbnail((label_w, label_h), Image.Resampling.LANCZOS)

                photo = ImageTk.PhotoImage(img)
                self.image_label.config(image=photo)
                self.image_label.image = photo # Keep a reference!
                self.status_bar.config(text=f"Diagram generated and displayed.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open or display diagram: {e}")
                self.status_bar.config(text="Error displaying diagram.")
        else:
            messagebox.showerror("Error", "Diagram file was not created.")
            self.status_bar.config(text="Failed to create diagram.")

def main():
    # Check for Pillow dependency for the GUI
    if not PILLOW_AVAILABLE:
        print("Pillow library not found. Please install it to run the GUI:")
        print("pip install Pillow")
        return

    app = NetworkMapperGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
