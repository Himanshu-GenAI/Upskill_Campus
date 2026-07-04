"""
main.py — Entry Point for Password Manager

Initialises the application:
1. Ensures the data/ directory exists.
2. Initialises the SQLite database.
3. Creates the Tkinter root window and launches the GUI.

Usage:
    python main.py
"""

import os
import sys
import customtkinter as ctk


def main():
    """Application entry point."""
    # Ensure we are running from the correct directory
    # (so that relative paths to data/ work correctly)
    app_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(app_dir)

    # Ensure data directory exists
    data_dir = os.path.join(app_dir, "data")
    os.makedirs(data_dir, exist_ok=True)

    # Import after chdir so module-level paths resolve correctly
    try:
        import db_manager
        import gui
    except ImportError as e:
        print(f"ERROR: Failed to import required modules: {e}")
        print("Make sure all project files are in the same directory.")
        sys.exit(1)

    # Initialise database
    try:
        db_manager.init_db()
    except Exception as e:
        print(f"ERROR: Failed to initialise database: {e}")
        sys.exit(1)

    # Configure CustomTkinter
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    # Create and configure the CustomTkinter root window
    root = ctk.CTk()
    root.title("Password Manager")

    # Set a minimum window size
    root.minsize(400, 350)

    # Handle window close — clear session data
    def on_closing():
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)

    # Launch the application
    try:
        app = gui.PasswordManagerApp(root)
        root.mainloop()
    except Exception as e:
        print(f"ERROR: Application crashed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
