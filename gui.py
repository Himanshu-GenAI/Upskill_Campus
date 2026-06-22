"""
gui.py — Portfolio-Quality Graphical User Interface for Password Manager using CustomTkinter

Implements all screens using CustomTkinter:
    1. Login Screen          — master password entry + verification + fade-in animation
    2. Setup Screen          — first-run master password creation (with strength meter)
    3. Dashboard             — welcome section, stats panel, credential list, search, and action sidebar
    4. Add Password Dialog   — modern form with live password strength meter + generator
    5. Edit Password Dialog  — modern pre-filled form with live strength meter
    6. Password Generator    — modern standalone generator with strength indicator and copy

Design notes:
- Uses CustomTkinter widgets for a premium dark look (rounded entries, buttons, checkboxes).
- Slate-dark design system aligned with modern styling guidelines.
- Responsive grid alignment and centered cards for setup/login windows.
- Memory-safe master password session key, cleared on logout.
- Bitwarden/1Password-inspired premium feel with animations.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os
from datetime import datetime
import customtkinter as ctk

import auth
import db_manager
import encryption
import password_gen

# ── Colour Palette & Styling ──────────────────────────────────────────────────

COLORS = {
    "bg_dark": "#0F172A",        # Tailwind slate-900
    "bg_mid": "#1E293B",         # Tailwind slate-800
    "bg_card": "#1E293B",        # Tailwind slate-800
    "bg_surface": "#162032",     # Slightly lighter than bg_dark for depth
    "primary": "#3B82F6",        # Tailwind blue-500
    "primary_hover": "#2563EB",  # Tailwind blue-600
    "primary_light": "#60A5FA",  # Tailwind blue-400
    "success": "#22C55E",        # Tailwind green-500
    "success_light": "#4ADE80",  # Tailwind green-400
    "warning": "#F59E0B",        # Tailwind amber-500 (changed from yellow)
    "error": "#EF4444",          # Tailwind red-500
    "text_primary": "#F8FAFC",    # Tailwind slate-50
    "text_secondary": "#94A3B8",  # Tailwind slate-400
    "text_muted": "#64748B",      # Tailwind slate-500
    "border": "#334155",          # Tailwind slate-700
    "border_light": "#475569",    # Tailwind slate-600
    "accent_purple": "#8B5CF6",   # Tailwind violet-500
}

FONT_FAMILY = "Segoe UI"

# App metadata
APP_VERSION = "v1.0"
APP_NAME = "Password Manager"


# ── Password Manager App Controller ───────────────────────────────────────────

class PasswordManagerApp:
    """Main application controller using CustomTkinter."""

    def __init__(self, root: ctk.CTk):
        self.root = root
        self.root.title("🔐 Password Manager")
        self.root.configure(fg_color=COLORS["bg_dark"])
        self.root.resizable(True, True)

        # Set appearance mode and color theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Session state
        self.master_password: str | None = None

        # Initialise database
        try:
            db_manager.init_db()
        except Exception as e:
            messagebox.showerror(
                "Database Error",
                f"Failed to initialise the database:\n{e}\n\n"
                "The application will now exit.",
            )
            sys.exit(1)

        # Configure ttk styles for the Treeview (since ctk has no native Treeview)
        self._configure_styles()

        # Container frame for screen switching
        self.container = ctk.CTkFrame(self.root, fg_color=COLORS["bg_dark"], corner_radius=0)
        self.container.pack(fill="both", expand=True)

        # Show the appropriate screen
        if auth.is_first_run():
            self._show_setup_screen()
        else:
            self._show_login_screen()

    def _configure_styles(self):
        """Set up ttk styling for a modern dark Treeview with alternating rows."""
        style = ttk.Style()
        style.theme_use("clam")

        # Treeview Configuration
        style.configure(
            "Vault.Treeview",
            background=COLORS["bg_mid"],
            foreground=COLORS["text_primary"],
            fieldbackground=COLORS["bg_mid"],
            font=(FONT_FAMILY, 11),
            rowheight=40,
            borderwidth=0,
        )
        style.configure(
            "Vault.Treeview.Heading",
            background="#334155",  # Tailwind slate-700
            foreground=COLORS["text_primary"],
            font=(FONT_FAMILY, 11, "bold"),
            borderwidth=0,
            relief="flat",
        )
        style.map(
            "Vault.Treeview",
            background=[("selected", COLORS["primary"])],
            foreground=[("selected", COLORS["text_primary"])],
        )

        # Remove treeview borders/gridlines for a cleaner card layout
        style.layout("Vault.Treeview", [('Vault.Treeview.treearea', {'sticky': 'nswe'})])

        # Configure tag-based alternating row colors
        # (applied in _refresh_credentials via tree.tag_configure)

    def _clear_container(self):
        """Destroy all child widgets in the container frame."""
        for widget in self.container.winfo_children():
            widget.destroy()

    def _center_window(self, width: int, height: int):
        """Centre the root window on the screen."""
        self.root.update_idletasks()
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        x = (screen_w - width) // 2
        y = (screen_h - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    # ── Fade-In Animation Utility ───────────────────────────────────────────

    def _fade_in(self, widget, start_alpha=0.0, target_alpha=1.0, step=0.05, delay=20):
        """Animate a widget's parent window from transparent to opaque."""
        try:
            self.root.attributes("-alpha", start_alpha)
            def _step(alpha):
                if alpha < target_alpha:
                    self.root.attributes("-alpha", alpha)
                    self.root.after(delay, lambda: _step(alpha + step))
                else:
                    self.root.attributes("-alpha", target_alpha)
            _step(start_alpha)
        except Exception:
            # Fallback: just show fully
            try:
                self.root.attributes("-alpha", 1.0)
            except Exception:
                pass

    # ── Live Password Strength Utility ──────────────────────────────────────

    def _update_strength_ui(self, password: str, label: ctk.CTkLabel, bar: ctk.CTkProgressBar):
        """Evaluate password strength and update UI elements in real-time."""
        if not password:
            label.configure(text="Strength: N/A", text_color=COLORS["text_muted"])
            bar.set(0.0)
            bar.configure(progress_color=COLORS["border"])
            return

        strength = password_gen.evaluate_strength(password)
        if strength == "Weak":
            label.configure(text="Strength: Weak 🔴", text_color=COLORS["error"])
            bar.set(0.33)
            bar.configure(progress_color=COLORS["error"])
        elif strength == "Medium":
            label.configure(text="Strength: Medium 🟡", text_color=COLORS["warning"])
            bar.set(0.66)
            bar.configure(progress_color=COLORS["warning"])
        else:
            label.configure(text="Strength: Strong 🟢", text_color=COLORS["success"])
            bar.set(1.0)
            bar.configure(progress_color=COLORS["success"])

    # ── Compute Security Score ──────────────────────────────────────────────

    def _compute_security_score(self, all_records):
        """
        Compute a numeric security score (0-100) based on password strengths.
        Returns (score, weak_count, medium_count, strong_count).
        """
        weak_count = 0
        medium_count = 0
        strong_count = 0
        total = len(all_records)

        if total == 0:
            return 0, 0, 0, 0

        for row in all_records:
            _, _, _, enc_pass, _, _, _ = row
            try:
                decrypted = encryption.decrypt_password(enc_pass, self.master_password)
                str_rating = password_gen.evaluate_strength(decrypted)
                if str_rating == "Weak":
                    weak_count += 1
                elif str_rating == "Medium":
                    medium_count += 1
                elif str_rating == "Strong":
                    strong_count += 1
            except Exception:
                weak_count += 1  # count decrypt errors as weak

        # Score: Strong = 100pts, Medium = 60pts, Weak = 20pts
        score = int(((strong_count * 100) + (medium_count * 60) + (weak_count * 20)) / total)
        return score, weak_count, medium_count, strong_count

    # ── Setup Screen (First Run) ──────────────────────────────────────────

    def _show_setup_screen(self):
        """Display the master password setup screen for first-time users."""
        self._clear_container()
        self._center_window(500, 580)

        # Centered Card Frame
        card = ctk.CTkFrame(
            self.container,
            fg_color=COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border"]
        )
        card.place(relx=0.5, rely=0.5, anchor="center")

        # Title
        ctk.CTkLabel(
            card, text="🔐", font=ctk.CTkFont(family=FONT_FAMILY, size=52)
        ).grid(row=0, column=0, columnspan=2, pady=(30, 5))

        ctk.CTkLabel(
            card, text="Welcome to Password Manager",
            font=ctk.CTkFont(family=FONT_FAMILY, size=22, weight="bold"),
            text_color=COLORS["text_primary"]
        ).grid(row=1, column=0, columnspan=2, pady=(0, 3), padx=40)

        ctk.CTkLabel(
            card, text="Create a master password to get started",
            font=ctk.CTkFont(family=FONT_FAMILY, size=13),
            text_color=COLORS["text_secondary"]
        ).grid(row=2, column=0, columnspan=2, pady=(0, 20))

        # Password Input
        ctk.CTkLabel(
            card, text="Master Password",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
            text_color=COLORS["text_secondary"]
        ).grid(row=3, column=0, columnspan=2, sticky="w", padx=30, pady=(10, 2))

        self.setup_pass_entry = ctk.CTkEntry(
            card, show="●", width=360, height=42,
            placeholder_text="🔒  Enter password (min 6 characters)",
            fg_color=COLORS["bg_dark"], border_color=COLORS["border"],
            text_color=COLORS["text_primary"], placeholder_text_color=COLORS["text_muted"],
            corner_radius=8
        )
        self.setup_pass_entry.grid(row=4, column=0, columnspan=2, padx=30, pady=(2, 5))

        # Confirm Password Input
        ctk.CTkLabel(
            card, text="Confirm Password",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
            text_color=COLORS["text_secondary"]
        ).grid(row=5, column=0, columnspan=2, sticky="w", padx=30, pady=(10, 2))

        self.setup_confirm_entry = ctk.CTkEntry(
            card, show="●", width=360, height=42,
            placeholder_text="🔒  Confirm password",
            fg_color=COLORS["bg_dark"], border_color=COLORS["border"],
            text_color=COLORS["text_primary"], placeholder_text_color=COLORS["text_muted"],
            corner_radius=8
        )
        self.setup_confirm_entry.grid(row=6, column=0, columnspan=2, padx=30, pady=(2, 10))

        # Real-time Password Strength Meter
        self.setup_strength_label = ctk.CTkLabel(
            card, text="Strength: N/A",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12),
            text_color=COLORS["text_muted"]
        )
        self.setup_strength_label.grid(row=7, column=0, columnspan=2, sticky="w", padx=32, pady=(0, 2))

        self.setup_strength_bar = ctk.CTkProgressBar(
            card, width=360, height=6, fg_color=COLORS["bg_dark"], progress_color=COLORS["border"],
            corner_radius=3
        )
        self.setup_strength_bar.grid(row=8, column=0, columnspan=2, padx=30, pady=(0, 10))
        self.setup_strength_bar.set(0.0)

        # Bind key release event for real-time strength meter
        self.setup_pass_entry.bind(
            "<KeyRelease>",
            lambda e: self._update_strength_ui(self.setup_pass_entry.get(), self.setup_strength_label, self.setup_strength_bar)
        )

        # Error label
        self.setup_error_label = ctk.CTkLabel(
            card, text="", font=ctk.CTkFont(family=FONT_FAMILY, size=12),
            text_color=COLORS["error"]
        )
        self.setup_error_label.grid(row=9, column=0, columnspan=2, pady=5)

        # Create button
        create_btn = ctk.CTkButton(
            card, text="Create Master Password",
            font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold"),
            fg_color=COLORS["primary"], hover_color=COLORS["primary_hover"],
            text_color=COLORS["text_primary"], height=44, width=360,
            corner_radius=8,
            command=self._handle_setup
        )
        create_btn.grid(row=10, column=0, columnspan=2, pady=(5, 15))

        # Version label at bottom of card
        ctk.CTkLabel(
            card, text=f"{APP_NAME} {APP_VERSION}",
            font=ctk.CTkFont(family=FONT_FAMILY, size=11),
            text_color=COLORS["text_muted"]
        ).grid(row=11, column=0, columnspan=2, pady=(0, 20))

        # Focus binds
        self.setup_confirm_entry.bind("<Return>", lambda e: self._handle_setup())
        self.setup_pass_entry.bind("<Return>", lambda e: self.setup_confirm_entry.focus())
        self.setup_pass_entry.focus_set()

        # Fade-in animation
        self._fade_in(self.container)

    def _handle_setup(self):
        """Process the master password setup form."""
        password = self.setup_pass_entry.get()
        confirm = self.setup_confirm_entry.get()

        if password != confirm:
            self.setup_error_label.configure(text="Passwords do not match.")
            return

        success, message = auth.setup_master_password(password)
        if success:
            messagebox.showinfo("Success", message)
            self._show_login_screen()
        else:
            self.setup_error_label.configure(text=message)

    # ── Login Screen ──────────────────────────────────────────────────────

    def _show_login_screen(self):
        """Display the login screen with fade-in animation."""
        self._clear_container()
        self._center_window(460, 500)
        self.master_password = None  # clear session

        # Centered Login Card
        card = ctk.CTkFrame(
            self.container,
            fg_color=COLORS["bg_card"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border"]
        )
        card.place(relx=0.5, rely=0.5, anchor="center")

        # Icon / title
        ctk.CTkLabel(
            card, text="🔐", font=ctk.CTkFont(family=FONT_FAMILY, size=56)
        ).grid(row=0, column=0, columnspan=2, pady=(30, 5))

        ctk.CTkLabel(
            card, text="Password Manager",
            font=ctk.CTkFont(family=FONT_FAMILY, size=22, weight="bold"),
            text_color=COLORS["text_primary"]
        ).grid(row=1, column=0, columnspan=2, pady=(0, 3), padx=40)

        # Subtitle
        ctk.CTkLabel(
            card, text="Manage your passwords securely",
            font=ctk.CTkFont(family=FONT_FAMILY, size=13),
            text_color=COLORS["text_secondary"]
        ).grid(row=2, column=0, columnspan=2, pady=(0, 25))

        # Password Entry Label
        ctk.CTkLabel(
            card, text="Master Password",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
            text_color=COLORS["text_secondary"]
        ).grid(row=3, column=0, columnspan=2, sticky="w", padx=30, pady=(10, 2))

        # Password Entry with show/hide toggle frame
        pass_frame = ctk.CTkFrame(card, fg_color="transparent")
        pass_frame.grid(row=4, column=0, columnspan=2, padx=30, pady=(2, 5))

        self.login_pass_entry = ctk.CTkEntry(
            pass_frame, show="●", width=300, height=42,
            placeholder_text="🔒  Enter master password",
            fg_color=COLORS["bg_dark"], border_color=COLORS["border"],
            text_color=COLORS["text_primary"], placeholder_text_color=COLORS["text_muted"],
            corner_radius=8
        )
        self.login_pass_entry.pack(side="left", padx=(0, 6))

        # Show/Hide Toggle Button
        self._login_show_pass = False
        self.login_toggle_btn = ctk.CTkButton(
            pass_frame, text="👁", width=42, height=42,
            fg_color=COLORS["bg_dark"], hover_color=COLORS["border"],
            border_color=COLORS["border"], border_width=1,
            text_color=COLORS["text_secondary"],
            font=ctk.CTkFont(size=16),
            corner_radius=8,
            command=self._toggle_login_password
        )
        self.login_toggle_btn.pack(side="right")

        # Error label
        self.login_error_label = ctk.CTkLabel(
            card, text="", font=ctk.CTkFont(family=FONT_FAMILY, size=12),
            text_color=COLORS["error"]
        )
        self.login_error_label.grid(row=5, column=0, columnspan=2, pady=5)

        # Login button
        login_btn = ctk.CTkButton(
            card, text="🔓  Unlock Vault",
            font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold"),
            fg_color=COLORS["primary"], hover_color=COLORS["primary_hover"],
            text_color=COLORS["text_primary"], height=44, width=360,
            corner_radius=8,
            command=self._handle_login
        )
        login_btn.grid(row=6, column=0, columnspan=2, pady=(5, 15))

        # Version label at bottom
        ctk.CTkLabel(
            card, text=f"{APP_NAME} {APP_VERSION}",
            font=ctk.CTkFont(family=FONT_FAMILY, size=11),
            text_color=COLORS["text_muted"]
        ).grid(row=7, column=0, columnspan=2, pady=(5, 25))

        # Bind Enter key
        self.login_pass_entry.bind("<Return>", lambda e: self._handle_login())
        self.login_pass_entry.focus_set()

        # Fade-in animation on startup
        self._fade_in(self.container)

    def _toggle_login_password(self):
        """Toggle password visibility in the login screen."""
        self._login_show_pass = not self._login_show_pass
        if self._login_show_pass:
            self.login_pass_entry.configure(show="")
            self.login_toggle_btn.configure(text="🙈")
        else:
            self.login_pass_entry.configure(show="●")
            self.login_toggle_btn.configure(text="👁")

    def _handle_login(self):
        """Verify the master password and proceed to the dashboard."""
        entered = self.login_pass_entry.get()

        if not entered:
            self.login_error_label.configure(text="Please enter your master password.")
            return

        try:
            if auth.verify_master_password(entered):
                self.master_password = entered
                self._show_dashboard()
            else:
                self.login_error_label.configure(text="Incorrect password. Please try again.")
                self.login_pass_entry.delete(0, tk.END)
        except FileNotFoundError:
            messagebox.showerror(
                "Error",
                "Master password file not found.\nThe application will restart in setup mode."
            )
            self._show_setup_screen()

    # ── Dashboard ─────────────────────────────────────────────────────────

    def _show_dashboard(self):
        """Display the main dashboard with welcome section, statistics, and layouts."""
        self._clear_container()
        self._center_window(1020, 700)

        # ── Top bar ──
        top_bar = ctk.CTkFrame(self.container, fg_color=COLORS["bg_mid"], height=56, corner_radius=0)
        top_bar.pack(fill="x")
        top_bar.pack_propagate(False)

        ctk.CTkLabel(
            top_bar, text="🔐 Password Vault",
            font=ctk.CTkFont(family=FONT_FAMILY, size=18, weight="bold"),
            text_color=COLORS["text_primary"]
        ).pack(side="left", padx=20)

        # Logout button
        logout_btn = ctk.CTkButton(
            top_bar, text="🚪 Logout", width=100, height=34,
            fg_color=COLORS["error"], hover_color="#DC2626",
            text_color=COLORS["text_primary"],
            font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
            corner_radius=6,
            command=self._handle_logout
        )
        logout_btn.pack(side="right", padx=20, pady=11)

        # ── Welcome Section ──
        welcome_frame = ctk.CTkFrame(self.container, fg_color=COLORS["bg_dark"], height=60)
        welcome_frame.pack(fill="x", padx=24, pady=(16, 0))
        welcome_frame.pack_propagate(False)

        ctk.CTkLabel(
            welcome_frame, text="Welcome back, Himanshu 👋",
            font=ctk.CTkFont(family=FONT_FAMILY, size=20, weight="bold"),
            text_color=COLORS["text_primary"]
        ).pack(anchor="w")

        ctk.CTkLabel(
            welcome_frame, text="Manage your passwords securely.",
            font=ctk.CTkFont(family=FONT_FAMILY, size=13),
            text_color=COLORS["text_secondary"]
        ).pack(anchor="w")

        # ── Main Content Container (Grid) ──
        main_grid = ctk.CTkFrame(self.container, fg_color=COLORS["bg_dark"])
        main_grid.pack(fill="both", expand=True, padx=24, pady=(12, 0))

        # Configure Grid Weights
        main_grid.columnconfigure(0, weight=1)  # Credentials & Stats
        main_grid.columnconfigure(1, weight=0)  # Sidebar actions
        main_grid.rowconfigure(0, weight=0)     # Stats Cards Row
        main_grid.rowconfigure(1, weight=0)     # Search & Filter Row
        main_grid.rowconfigure(2, weight=1)     # Treeview Row

        # ── 1. Statistics Cards Panel ──
        stats_frame = ctk.CTkFrame(main_grid, fg_color=COLORS["bg_dark"])
        stats_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 12))

        # Setup stats grid columns (three responsive cards)
        stats_frame.columnconfigure(0, weight=1)
        stats_frame.columnconfigure(1, weight=1)
        stats_frame.columnconfigure(2, weight=1)

        # Card 1: Total Passwords
        card_total = ctk.CTkFrame(stats_frame, fg_color=COLORS["bg_card"], border_color=COLORS["border"], border_width=1, corner_radius=10, height=95)
        card_total.grid(row=0, column=0, padx=(0, 8), sticky="ew")
        card_total.grid_propagate(False)

        ctk.CTkLabel(card_total, text="🔐", font=ctk.CTkFont(size=20)).pack(anchor="w", padx=18, pady=(14, 0))
        self.stat_total_label = ctk.CTkLabel(card_total, text="0", font=ctk.CTkFont(family=FONT_FAMILY, size=26, weight="bold"), text_color=COLORS["primary"])
        self.stat_total_label.pack(anchor="w", padx=18, pady=(2, 0))
        ctk.CTkLabel(card_total, text="Total Passwords", font=ctk.CTkFont(family=FONT_FAMILY, size=11), text_color=COLORS["text_secondary"]).pack(anchor="w", padx=18)

        # Card 2: Security Score
        card_status = ctk.CTkFrame(stats_frame, fg_color=COLORS["bg_card"], border_color=COLORS["border"], border_width=1, corner_radius=10, height=95)
        card_status.grid(row=0, column=1, padx=4, sticky="ew")
        card_status.grid_propagate(False)

        ctk.CTkLabel(card_status, text="🛡️", font=ctk.CTkFont(size=20)).pack(anchor="w", padx=18, pady=(14, 0))

        score_row = ctk.CTkFrame(card_status, fg_color="transparent")
        score_row.pack(anchor="w", padx=18, pady=(2, 0))
        self.stat_score_label = ctk.CTkLabel(score_row, text="—/100", font=ctk.CTkFont(family=FONT_FAMILY, size=22, weight="bold"), text_color=COLORS["success"])
        self.stat_score_label.pack(side="left")
        self.stat_status_text = ctk.CTkLabel(score_row, text="", font=ctk.CTkFont(family=FONT_FAMILY, size=11), text_color=COLORS["text_secondary"])
        self.stat_status_text.pack(side="left", padx=(8, 0))

        self.stat_score_bar = ctk.CTkProgressBar(card_status, height=5, fg_color=COLORS["bg_dark"], progress_color=COLORS["success"], corner_radius=3)
        self.stat_score_bar.pack(fill="x", padx=18, pady=(4, 0))
        self.stat_score_bar.set(0.0)

        # Card 3: Last Updated Time
        card_updated = ctk.CTkFrame(stats_frame, fg_color=COLORS["bg_card"], border_color=COLORS["border"], border_width=1, corner_radius=10, height=95)
        card_updated.grid(row=0, column=2, padx=(8, 0), sticky="ew")
        card_updated.grid_propagate(False)

        ctk.CTkLabel(card_updated, text="📅", font=ctk.CTkFont(size=20)).pack(anchor="w", padx=18, pady=(14, 0))
        self.stat_updated_label = ctk.CTkLabel(card_updated, text="N/A", font=ctk.CTkFont(family=FONT_FAMILY, size=20, weight="bold"), text_color=COLORS["text_primary"])
        self.stat_updated_label.pack(anchor="w", padx=18, pady=(2, 0))
        ctk.CTkLabel(card_updated, text="Last Updated", font=ctk.CTkFont(family=FONT_FAMILY, size=11), text_color=COLORS["text_secondary"]).pack(anchor="w", padx=18)

        # ── 2. Search Box ──
        search_frame = ctk.CTkFrame(main_grid, fg_color=COLORS["bg_dark"])
        search_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._refresh_credentials())

        self.search_entry = ctk.CTkEntry(
            search_frame, textvariable=self.search_var,
            placeholder_text="🔍  Search websites, usernames...",
            height=40, fg_color=COLORS["bg_card"], border_color=COLORS["border"],
            text_color=COLORS["text_primary"], placeholder_text_color=COLORS["text_secondary"],
            corner_radius=8
        )
        self.search_entry.pack(fill="x", expand=True)

        # ── 3. Treeview Panel (Credentials List) ──
        tree_card = ctk.CTkFrame(
            main_grid, fg_color=COLORS["bg_card"], border_color=COLORS["border"], border_width=1, corner_radius=10
        )
        tree_card.grid(row=2, column=0, sticky="nsew", padx=(0, 12))

        columns = ("id", "website", "username", "password", "notes", "created", "action")
        self.tree = ttk.Treeview(
            tree_card, columns=columns, show="headings",
            style="Vault.Treeview", selectmode="browse"
        )

        # Configure column headers and widths
        self.tree.heading("id", text="ID")
        self.tree.heading("website", text="Website / App")
        self.tree.heading("username", text="Username")
        self.tree.heading("password", text="Password")
        self.tree.heading("notes", text="Notes")
        self.tree.heading("created", text="Created")
        self.tree.heading("action", text="Action")

        self.tree.column("id", width=40, minwidth=40, stretch=False)
        self.tree.column("website", width=130, minwidth=100)
        self.tree.column("username", width=140, minwidth=100)
        self.tree.column("password", width=100, minwidth=80)
        self.tree.column("notes", width=120, minwidth=80)
        self.tree.column("created", width=120, minwidth=100, stretch=False)
        self.tree.column("action", width=80, minwidth=80, stretch=False, anchor="center")

        # Configure alternating row tags
        self.tree.tag_configure("row_even", background=COLORS["bg_mid"])
        self.tree.tag_configure("row_odd", background=COLORS["bg_surface"])
        # Hover-like effect for copy column
        self.tree.tag_configure("row_even", foreground=COLORS["text_primary"])
        self.tree.tag_configure("row_odd", foreground=COLORS["text_primary"])

        # Customize Scrollbar
        scrollbar = ttk.Scrollbar(tree_card, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=10)

        # Bind double-click to Edit dialog
        self.tree.bind("<Double-1>", lambda e: self._show_edit_dialog())
        # Bind click to copy action
        self.tree.bind("<ButtonRelease-1>", self._on_tree_click)
        # Bind mouse movement to change cursor over copy column
        self.tree.bind("<Motion>", self._on_tree_motion)

        sidebar = ctk.CTkFrame(main_grid, fg_color=COLORS["bg_dark"])
        sidebar.grid(row=2, column=1, sticky="ns")

        sidebar_buttons = [
            ("➕ Add Password", COLORS["primary"], COLORS["primary_hover"], self._show_add_dialog),
            ("✏️ Edit Entry", COLORS["bg_card"], "#334155", self._show_edit_dialog),
            ("🗑️ Delete Entry", COLORS["error"], "#DC2626", self._handle_delete),
            ("📋 Copy Password", COLORS["success"], "#16A34A", self._handle_copy_password),
            ("🎲 Generator", COLORS["bg_card"], "#334155", self._show_generator_dialog)
        ]

        for text, bg_color, hover_color, cmd in sidebar_buttons:
            btn = ctk.CTkButton(
                sidebar, text=text, font=ctk.CTkFont(family=FONT_FAMILY, size=13, weight="bold"),
                fg_color=bg_color, hover_color=hover_color, text_color=COLORS["text_primary"],
                width=160, height=40, corner_radius=8, command=cmd
            )
            btn.pack(pady=(0, 10))

        # ── Footer Bar ──
        footer = ctk.CTkFrame(self.container, fg_color=COLORS["bg_mid"], height=36, corner_radius=0)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)

        ctk.CTkLabel(
            footer, text=f"{APP_NAME} {APP_VERSION}",
            font=ctk.CTkFont(family=FONT_FAMILY, size=11),
            text_color=COLORS["text_muted"]
        ).pack(side="left", padx=20)

        ctk.CTkLabel(
            footer, text="Built with Python + SQLite + Fernet",
            font=ctk.CTkFont(family=FONT_FAMILY, size=11),
            text_color=COLORS["text_muted"]
        ).pack(side="right", padx=20)

        # Status label (between main content and footer)
        self.status_label = ctk.CTkLabel(
            self.container, text="", font=ctk.CTkFont(family=FONT_FAMILY, size=12),
            text_color=COLORS["text_muted"], anchor="w"
        )
        self.status_label.pack(fill="x", padx=24, pady=(0, 4), before=footer)

        # Initial Refresh to load stats & grid data
        self._refresh_credentials()

    def _refresh_credentials(self):
        """Reload Treeview data and update statistics in cards."""
        # Clear existing treeview items
        for item in self.tree.get_children():
            self.tree.delete(item)

        try:
            # Query backend
            query = self.search_var.get().strip() if hasattr(self, 'search_var') else ""
            if query:
                rows = db_manager.search_credentials(query)
            else:
                rows = db_manager.get_all_credentials()

            for idx, row in enumerate(rows):
                cred_id, website, username, enc_pass, notes, created_at, _ = row
                try:
                    decrypted = encryption.decrypt_password(enc_pass, self.master_password)
                    display_pass = "●" * min(len(decrypted), 12)
                except Exception:
                    display_pass = "⚠ Decryption error"

                created_display = created_at[:16] if created_at else "N/A"
                tag = "row_even" if idx % 2 == 0 else "row_odd"
                self.tree.insert(
                    "", "end",
                    values=(
                        cred_id, website, username,
                        display_pass, notes or "", created_display,
                        "📋 Copy"
                    ),
                    tags=(tag,)
                )

            # --- Update Statistics Panels ---
            all_records = db_manager.get_all_credentials()
            total_count = len(all_records)
            self.stat_total_label.configure(text=str(total_count))

            # Security Score
            score, weak_count, medium_count, strong_count = self._compute_security_score(all_records)

            if total_count == 0:
                self.stat_score_label.configure(text="—/100", text_color=COLORS["text_muted"])
                self.stat_status_text.configure(text="No passwords")
                self.stat_score_bar.set(0.0)
                self.stat_score_bar.configure(progress_color=COLORS["border"])
            else:
                self.stat_score_label.configure(text=f"{score}/100")
                self.stat_score_bar.set(score / 100.0)

                if score >= 80:
                    self.stat_score_label.configure(text_color=COLORS["success"])
                    self.stat_status_text.configure(text="Strong")
                    self.stat_score_bar.configure(progress_color=COLORS["success"])
                elif score >= 50:
                    self.stat_score_label.configure(text_color=COLORS["warning"])
                    self.stat_status_text.configure(text="Medium")
                    self.stat_score_bar.configure(progress_color=COLORS["warning"])
                else:
                    self.stat_score_label.configure(text_color=COLORS["error"])
                    self.stat_status_text.configure(text=f"Weak ({weak_count} warning{'s' if weak_count > 1 else ''})")
                    self.stat_score_bar.configure(progress_color=COLORS["error"])

            # Last Updated
            latest_time = None
            for row in all_records:
                _, _, _, _, _, created_at, updated_at = row
                for t_str in [updated_at, created_at]:
                    if t_str:
                        try:
                            t_val = datetime.strptime(t_str, "%Y-%m-%d %H:%M:%S")
                            if latest_time is None or t_val > latest_time:
                                latest_time = t_val
                        except ValueError:
                            pass

            if latest_time:
                self.stat_updated_label.configure(text=latest_time.strftime("%b %d, %H:%M"))
            else:
                self.stat_updated_label.configure(text="N/A")

            # Update footer status
            self.status_label.configure(text=f"Showing {len(rows)} of {total_count} credential{'s' if total_count != 1 else ''} stored.")

            # Clear Treeview selections
            self.tree.selection_remove(self.tree.selection())

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load credentials:\n{e}")

    def _get_selected_credential(self) -> tuple | None:
        """Fetch selected credential from treeview; displays warning if none selected."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a credential from the list.")
            return None

        item = self.tree.item(selection[0])
        cred_id = int(item["values"][0])
        return db_manager.get_credential_by_id(cred_id)

    def _on_tree_click(self, event):
        """Detect click on the 'Copy' action column of a row."""
        region = self.tree.identify_region(event.x, event.y)
        if region == "cell":
            column_str = self.tree.identify_column(event.x)
            # Find logical column ID
            try:
                col_idx = int(column_str.replace("#", "")) - 1
                col_id = self.tree["columns"][col_idx]
            except Exception:
                col_id = ""

            if col_id == "action" or column_str == "#7":
                item = self.tree.identify_row(event.y)
                if item:
                    values = self.tree.item(item, "values")
                    cred_id = int(values[0])
                    # Fetch from database to get encrypted password
                    cred = db_manager.get_credential_by_id(cred_id)
                    if cred:
                        enc_pass = cred[3]
                        website = cred[1]
                        try:
                            decrypted = encryption.decrypt_password(enc_pass, self.master_password)
                            self.root.clipboard_clear()
                            self.root.clipboard_append(decrypted)
                            self.status_label.configure(
                                text=f"✅ Password for '{website}' copied to clipboard!",
                                text_color=COLORS["success"]
                            )
                            # Reset status text after 3 seconds
                            self.root.after(3000, self._reset_status_label)
                        except Exception as e:
                            messagebox.showerror("Error", f"Failed to decrypt password:\n{e}")

    def _on_tree_motion(self, event):
        """Change mouse cursor when hovering over the clickable 'Copy' column."""
        region = self.tree.identify_region(event.x, event.y)
        if region == "cell":
            column_str = self.tree.identify_column(event.x)
            try:
                col_idx = int(column_str.replace("#", "")) - 1
                col_id = self.tree["columns"][col_idx]
            except Exception:
                col_id = ""
            
            if col_id == "action":
                self.tree.configure(cursor="hand2")
                return
        
        self.tree.configure(cursor="")

    def _handle_copy_password(self):
        """Copy selected credential password to clipboard."""
        cred = self._get_selected_credential()
        if cred is None:
            return
        
        website, enc_pass = cred[1], cred[3]
        try:
            decrypted = encryption.decrypt_password(enc_pass, self.master_password)
            self.root.clipboard_clear()
            self.root.clipboard_append(decrypted)
            self.status_label.configure(
                text=f"✅ Password for '{website}' copied to clipboard!",
                text_color=COLORS["success"]
            )
            self.root.after(3000, self._reset_status_label)
            messagebox.showinfo("Copied", f"Password for '{website}' copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt password:\n{e}")

    def _reset_status_label(self):
        """Reset the footer status text to show overall count."""
        try:
            total_count = len(db_manager.get_all_credentials())
            shown_count = len(self.tree.get_children())
            self.status_label.configure(
                text=f"Showing {shown_count} of {total_count} credential{'s' if total_count != 1 else ''} stored.",
                text_color=COLORS["text_muted"]
            )
        except Exception:
            pass

    # ── Logout ────────────────────────────────────────────────────────────

    def _handle_logout(self):
        """Clear master password and return to login screen."""
        self.master_password = None
        self._show_login_screen()

    # ── Delete ────────────────────────────────────────────────────────────

    def _handle_delete(self):
        """Prompt confirmation and delete credentials."""
        cred = self._get_selected_credential()
        if cred is None:
            return

        cred_id, website, username = cred[0], cred[1], cred[2]

        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete the credential for:\n\n"
            f"  Website:  {website}\n"
            f"  Username: {username}\n\n"
            f"This action cannot be undone.",
            icon='warning'
        )

        if confirm:
            try:
                db_manager.delete_credential(cred_id)
                self._refresh_credentials()
                messagebox.showinfo("Deleted", "Credential deleted successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete credential:\n{e}")

    # ── Add Password Dialog ───────────────────────────────────────────────

    def _show_add_dialog(self):
        """Open Add Password popup form with CustomTkinter inputs."""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Add New Password")
        dialog.configure(fg_color=COLORS["bg_dark"])
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        # Center Dialog window
        dialog.geometry("500x640")
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - 500) // 2
        y = (dialog.winfo_screenheight() - 640) // 2
        dialog.geometry(f"+{x}+{y}")
        dialog.lift()

        # Add visual layout Card Frame
        card = ctk.CTkFrame(dialog, fg_color=COLORS["bg_card"], border_color=COLORS["border"], border_width=1, corner_radius=14)
        card.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        ctk.CTkLabel(
            card, text="➕ Add New Password",
            font=ctk.CTkFont(family=FONT_FAMILY, size=18, weight="bold"),
            text_color=COLORS["text_primary"]
        ).pack(anchor="w", padx=25, pady=(20, 15))

        # Fields Setup
        entries = {}

        # Website
        ctk.CTkLabel(card, text="Website / App", font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"), text_color=COLORS["text_secondary"]).pack(anchor="w", padx=25, pady=(5, 1))
        web_entry = ctk.CTkEntry(card, placeholder_text="e.g. google.com", fg_color=COLORS["bg_dark"], border_color=COLORS["border"], height=38, text_color=COLORS["text_primary"], corner_radius=8)
        web_entry.pack(fill="x", padx=25, pady=(0, 8))
        entries["Website / App"] = web_entry

        # Username
        ctk.CTkLabel(card, text="Username / Email", font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"), text_color=COLORS["text_secondary"]).pack(anchor="w", padx=25, pady=(5, 1))
        user_entry = ctk.CTkEntry(card, placeholder_text="e.g. user@gmail.com", fg_color=COLORS["bg_dark"], border_color=COLORS["border"], height=38, text_color=COLORS["text_primary"], corner_radius=8)
        user_entry.pack(fill="x", padx=25, pady=(0, 8))
        entries["Username"] = user_entry

        # Password Entry & Generate Buttons Layout
        ctk.CTkLabel(card, text="Password", font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"), text_color=COLORS["text_secondary"]).pack(anchor="w", padx=25, pady=(5, 1))
        pass_frame = ctk.CTkFrame(card, fg_color="transparent")
        pass_frame.pack(fill="x", padx=25, pady=(0, 2))

        pass_entry = ctk.CTkEntry(pass_frame, show="●", placeholder_text="Enter password", fg_color=COLORS["bg_dark"], border_color=COLORS["border"], height=38, text_color=COLORS["text_primary"], corner_radius=8)
        pass_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        entries["Password"] = pass_entry

        # Generate Button
        def fill_generated():
            try:
                pwd = password_gen.generate_password(16, True, True, True)
                pass_entry.delete(0, tk.END)
                pass_entry.insert(0, pwd)
                self._update_strength_ui(pwd, strength_label, strength_bar)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate password:\n{e}")

        gen_btn = ctk.CTkButton(
            pass_frame, text="🎲 Generate", width=100, height=38,
            fg_color=COLORS["bg_dark"], hover_color="#334155",
            border_color=COLORS["border"], border_width=1,
            text_color=COLORS["text_primary"], font=ctk.CTkFont(family=FONT_FAMILY, size=11, weight="bold"),
            corner_radius=8,
            command=fill_generated
        )
        gen_btn.pack(side="right")

        # Strength Indicator & progress bar
        strength_label = ctk.CTkLabel(card, text="Strength: N/A", font=ctk.CTkFont(family=FONT_FAMILY, size=12), text_color=COLORS["text_muted"])
        strength_label.pack(anchor="w", padx=27, pady=(2, 1))
        strength_bar = ctk.CTkProgressBar(card, height=6, fg_color=COLORS["bg_dark"], progress_color=COLORS["border"], corner_radius=3)
        strength_bar.pack(fill="x", padx=25, pady=(0, 8))
        strength_bar.set(0.0)

        # Bind KeyRelease on password entry
        pass_entry.bind("<KeyRelease>", lambda e: self._update_strength_ui(pass_entry.get(), strength_label, strength_bar))

        # Show/Hide Toggle Checkbox
        show_var = tk.BooleanVar(value=False)
        def toggle_password():
            pass_entry.configure(show="" if show_var.get() else "●")

        show_check = ctk.CTkCheckBox(
            card, text="Show password", variable=show_var, command=toggle_password,
            font=ctk.CTkFont(family=FONT_FAMILY, size=11), text_color=COLORS["text_secondary"],
            checkbox_width=16, checkbox_height=16
        )
        show_check.pack(anchor="w", padx=25, pady=(2, 8))

        # Notes Box
        ctk.CTkLabel(card, text="Notes (Optional)", font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"), text_color=COLORS["text_secondary"]).pack(anchor="w", padx=25, pady=(5, 1))
        notes_box = ctk.CTkTextbox(card, height=60, fg_color=COLORS["bg_dark"], border_color=COLORS["border"], border_width=1, text_color=COLORS["text_primary"], font=(FONT_FAMILY, 11), corner_radius=8)
        notes_box.pack(fill="x", padx=25, pady=(0, 10))
        entries["Notes"] = notes_box

        # Error label
        error_label = ctk.CTkLabel(card, text="", font=ctk.CTkFont(family=FONT_FAMILY, size=12), text_color=COLORS["error"])
        error_label.pack(pady=3)

        # Save Action Button
        def handle_save():
            website = web_entry.get().strip()
            username = user_entry.get().strip()
            password = pass_entry.get().strip()
            notes = notes_box.get("1.0", "end").strip()

            if not website:
                error_label.configure(text="Website / App name is required.")
                return
            if not username:
                error_label.configure(text="Username is required.")
                return
            if not password:
                error_label.configure(text="Password is required.")
                return

            try:
                enc_pass = encryption.encrypt_password(password, self.master_password)
                db_manager.insert_credential(website, username, enc_pass, notes)
                dialog.destroy()
                self._refresh_credentials()
                messagebox.showinfo("Saved", "Password stored successfully!")
            except Exception as e:
                error_label.configure(text=f"Save failed: {e}")

        # Actions Layout (Save and Cancel)
        actions_frame = ctk.CTkFrame(card, fg_color="transparent")
        actions_frame.pack(fill="x", padx=25, pady=(5, 20))
        actions_frame.columnconfigure(0, weight=1)
        actions_frame.columnconfigure(1, weight=1)

        cancel_btn = ctk.CTkButton(
            actions_frame, text="❌ Cancel",
            font=ctk.CTkFont(family=FONT_FAMILY, size=13, weight="bold"),
            fg_color=COLORS["bg_dark"], hover_color="#334155",
            border_color=COLORS["border"], border_width=1,
            text_color=COLORS["text_primary"], height=42,
            corner_radius=8,
            command=dialog.destroy
        )
        cancel_btn.grid(row=0, column=0, padx=(0, 6), sticky="ew")

        save_btn = ctk.CTkButton(
            actions_frame, text="💾 Save",
            font=ctk.CTkFont(family=FONT_FAMILY, size=13, weight="bold"),
            fg_color=COLORS["primary"], hover_color=COLORS["primary_hover"],
            text_color=COLORS["text_primary"], height=42,
            corner_radius=8,
            command=handle_save
        )
        save_btn.grid(row=0, column=1, padx=(6, 0), sticky="ew")

        web_entry.focus_set()

    # ── Edit Password Dialog ──────────────────────────────────────────────

    def _show_edit_dialog(self):
        """Open Edit Password popup prefilled with selected credential."""
        cred = self._get_selected_credential()
        if cred is None:
            return

        cred_id, website, username, enc_pass, notes, created_at, updated_at = cred

        # Decrypt password for editing
        try:
            current_password = encryption.decrypt_password(enc_pass, self.master_password)
        except Exception:
            messagebox.showerror(
                "Decryption Error",
                "Could not decrypt this credential. The data may be corrupted."
            )
            return

        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Edit Password")
        dialog.configure(fg_color=COLORS["bg_dark"])
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        dialog.geometry("500x660")
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - 500) // 2
        y = (dialog.winfo_screenheight() - 660) // 2
        dialog.geometry(f"+{x}+{y}")
        dialog.lift()

        # Layout Card Frame
        card = ctk.CTkFrame(dialog, fg_color=COLORS["bg_card"], border_color=COLORS["border"], border_width=1, corner_radius=14)
        card.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        ctk.CTkLabel(
            card, text="✏️ Edit Password",
            font=ctk.CTkFont(family=FONT_FAMILY, size=18, weight="bold"),
            text_color=COLORS["text_primary"]
        ).pack(anchor="w", padx=25, pady=(20, 15))

        # Fields
        # Website
        ctk.CTkLabel(card, text="Website / App", font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"), text_color=COLORS["text_secondary"]).pack(anchor="w", padx=25, pady=(5, 1))
        web_entry = ctk.CTkEntry(card, fg_color=COLORS["bg_dark"], border_color=COLORS["border"], height=38, text_color=COLORS["text_primary"], corner_radius=8)
        web_entry.pack(fill="x", padx=25, pady=(0, 8))
        web_entry.insert(0, website)

        # Username
        ctk.CTkLabel(card, text="Username / Email", font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"), text_color=COLORS["text_secondary"]).pack(anchor="w", padx=25, pady=(5, 1))
        user_entry = ctk.CTkEntry(card, fg_color=COLORS["bg_dark"], border_color=COLORS["border"], height=38, text_color=COLORS["text_primary"], corner_radius=8)
        user_entry.pack(fill="x", padx=25, pady=(0, 8))
        user_entry.insert(0, username)

        # Password layout with Generate Button
        ctk.CTkLabel(card, text="Password", font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"), text_color=COLORS["text_secondary"]).pack(anchor="w", padx=25, pady=(5, 1))
        pass_frame = ctk.CTkFrame(card, fg_color="transparent")
        pass_frame.pack(fill="x", padx=25, pady=(0, 2))

        pass_entry = ctk.CTkEntry(pass_frame, show="●", fg_color=COLORS["bg_dark"], border_color=COLORS["border"], height=38, text_color=COLORS["text_primary"], corner_radius=8)
        pass_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        pass_entry.insert(0, current_password)

        def fill_generated():
            try:
                pwd = password_gen.generate_password(16, True, True, True)
                pass_entry.delete(0, tk.END)
                pass_entry.insert(0, pwd)
                self._update_strength_ui(pwd, strength_label, strength_bar)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate password:\n{e}")

        gen_btn = ctk.CTkButton(
            pass_frame, text="🎲 Generate", width=100, height=38,
            fg_color=COLORS["bg_dark"], hover_color="#334155",
            border_color=COLORS["border"], border_width=1,
            text_color=COLORS["text_primary"], font=ctk.CTkFont(family=FONT_FAMILY, size=11, weight="bold"),
            corner_radius=8,
            command=fill_generated
        )
        gen_btn.pack(side="right")

        # Strength Meter
        strength_label = ctk.CTkLabel(card, text="Strength: N/A", font=ctk.CTkFont(family=FONT_FAMILY, size=12), text_color=COLORS["text_muted"])
        strength_label.pack(anchor="w", padx=27, pady=(2, 1))
        strength_bar = ctk.CTkProgressBar(card, height=6, fg_color=COLORS["bg_dark"], progress_color=COLORS["border"], corner_radius=3)
        strength_bar.pack(fill="x", padx=25, pady=(0, 8))
        strength_bar.set(0.0)

        # Bind KeyRelease on password entry
        pass_entry.bind("<KeyRelease>", lambda e: self._update_strength_ui(pass_entry.get(), strength_label, strength_bar))
        self._update_strength_ui(current_password, strength_label, strength_bar)

        # Show/Hide Toggle Checkbox
        show_var = tk.BooleanVar(value=False)
        def toggle_password():
            pass_entry.configure(show="" if show_var.get() else "●")

        show_check = ctk.CTkCheckBox(
            card, text="Show password", variable=show_var, command=toggle_password,
            font=ctk.CTkFont(family=FONT_FAMILY, size=11), text_color=COLORS["text_secondary"],
            checkbox_width=16, checkbox_height=16
        )
        show_check.pack(anchor="w", padx=25, pady=(2, 8))

        # Notes Box
        ctk.CTkLabel(card, text="Notes (Optional)", font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"), text_color=COLORS["text_secondary"]).pack(anchor="w", padx=25, pady=(5, 1))
        notes_box = ctk.CTkTextbox(card, height=60, fg_color=COLORS["bg_dark"], border_color=COLORS["border"], border_width=1, text_color=COLORS["text_primary"], font=(FONT_FAMILY, 11), corner_radius=8)
        notes_box.pack(fill="x", padx=25, pady=(0, 8))
        notes_box.insert("1.0", notes or "")

        # Dates / Timestamps Label
        date_text = f"Created: {created_at[:16] if created_at else 'N/A'}  |  Updated: {updated_at[:16] if updated_at else 'N/A'}"
        date_lbl = ctk.CTkLabel(card, text=date_text, font=ctk.CTkFont(family=FONT_FAMILY, size=10), text_color=COLORS["text_muted"])
        date_lbl.pack(anchor="w", padx=25, pady=(2, 2))

        # Error label
        error_label = ctk.CTkLabel(card, text="", font=ctk.CTkFont(family=FONT_FAMILY, size=12), text_color=COLORS["error"])
        error_label.pack(pady=2)

        # Update Action Button
        def handle_update():
            new_website = web_entry.get().strip()
            new_username = user_entry.get().strip()
            new_password = pass_entry.get().strip()
            new_notes = notes_box.get("1.0", "end").strip()

            if not new_website:
                error_label.configure(text="Website / App name is required.")
                return
            if not new_username:
                error_label.configure(text="Username is required.")
                return
            if not new_password:
                error_label.configure(text="Password is required.")
                return

            try:
                enc_pass_new = encryption.encrypt_password(new_password, self.master_password)
                db_manager.update_credential(cred_id, new_website, new_username, enc_pass_new, new_notes)
                dialog.destroy()
                self._refresh_credentials()
                messagebox.showinfo("Updated", "Password updated successfully!")
            except Exception as e:
                error_label.configure(text=f"Update failed: {e}")

        # Actions Layout (Update and Cancel)
        actions_frame = ctk.CTkFrame(card, fg_color="transparent")
        actions_frame.pack(fill="x", padx=25, pady=(5, 20))
        actions_frame.columnconfigure(0, weight=1)
        actions_frame.columnconfigure(1, weight=1)

        cancel_btn = ctk.CTkButton(
            actions_frame, text="❌ Cancel",
            font=ctk.CTkFont(family=FONT_FAMILY, size=13, weight="bold"),
            fg_color=COLORS["bg_dark"], hover_color="#334155",
            border_color=COLORS["border"], border_width=1,
            text_color=COLORS["text_primary"], height=42,
            corner_radius=8,
            command=dialog.destroy
        )
        cancel_btn.grid(row=0, column=0, padx=(0, 6), sticky="ew")

        update_btn = ctk.CTkButton(
            actions_frame, text="💾 Update",
            font=ctk.CTkFont(family=FONT_FAMILY, size=13, weight="bold"),
            fg_color=COLORS["primary"], hover_color=COLORS["primary_hover"],
            text_color=COLORS["text_primary"], height=42,
            corner_radius=8,
            command=handle_update
        )
        update_btn.grid(row=0, column=1, padx=(6, 0), sticky="ew")

        web_entry.focus_set()

    # ── Password Generator Dialog ─────────────────────────────────────────

    def _show_generator_dialog(self):
        """Open standalone Password Generator dialog using CustomTkinter controls."""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Password Generator")
        dialog.configure(fg_color=COLORS["bg_dark"])
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        dialog.geometry("500x540")
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - 500) // 2
        y = (dialog.winfo_screenheight() - 540) // 2
        dialog.geometry(f"+{x}+{y}")
        dialog.lift()

        # Layout Card Frame
        card = ctk.CTkFrame(dialog, fg_color=COLORS["bg_card"], border_color=COLORS["border"], border_width=1, corner_radius=14)
        card.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        ctk.CTkLabel(
            card, text="🎲 Password Generator",
            font=ctk.CTkFont(family=FONT_FAMILY, size=18, weight="bold"),
            text_color=COLORS["text_primary"]
        ).pack(anchor="w", padx=25, pady=(20, 15))

        # Slider config
        length_frame = ctk.CTkFrame(card, fg_color="transparent")
        length_frame.pack(fill="x", padx=25, pady=5)

        ctk.CTkLabel(length_frame, text="Password Length", font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"), text_color=COLORS["text_secondary"]).pack(side="left")
        length_label = ctk.CTkLabel(length_frame, text="16", font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold"), text_color=COLORS["primary"])
        length_label.pack(side="right")

        length_var = tk.IntVar(value=16)
        def update_length_label(val):
            length_label.configure(text=str(int(float(val))))

        length_slider = ctk.CTkSlider(
            card, from_=4, to=64, number_of_steps=60,
            variable=length_var, command=update_length_label,
            fg_color=COLORS["bg_dark"], progress_color=COLORS["primary"]
        )
        length_slider.pack(fill="x", padx=25, pady=(0, 15))

        # Checkboxes
        upper_var = tk.BooleanVar(value=True)
        digits_var = tk.BooleanVar(value=True)
        symbols_var = tk.BooleanVar(value=True)

        chk_opts = {"font": ctk.CTkFont(family=FONT_FAMILY, size=12), "text_color": COLORS["text_secondary"], "checkbox_width": 18, "checkbox_height": 18}

        chk_upper = ctk.CTkCheckBox(card, text="Include Uppercase (A-Z)", variable=upper_var, **chk_opts)
        chk_upper.pack(anchor="w", padx=25, pady=4)

        chk_digits = ctk.CTkCheckBox(card, text="Include Digits (0-9)", variable=digits_var, **chk_opts)
        chk_digits.pack(anchor="w", padx=25, pady=4)

        chk_symbols = ctk.CTkCheckBox(card, text="Include Symbols (!@#$...)", variable=symbols_var, **chk_opts)
        chk_symbols.pack(anchor="w", padx=25, pady=(4, 15))

        # Result field
        result_entry = ctk.CTkEntry(
            card, font=ctk.CTkFont(family=FONT_FAMILY, size=14, weight="bold"), height=44,
            fg_color=COLORS["bg_dark"], border_color=COLORS["border"], text_color=COLORS["success"],
            justify="center", corner_radius=8
        )
        result_entry.pack(fill="x", padx=25, pady=2)

        # Strength rating Label
        strength_label = ctk.CTkLabel(card, text="Strength: N/A", font=ctk.CTkFont(family=FONT_FAMILY, size=12), text_color=COLORS["text_muted"])
        strength_label.pack(pady=(2, 15))

        # Generate action
        def do_generate():
            try:
                pwd = password_gen.generate_password(
                    length=length_var.get(),
                    use_upper=upper_var.get(),
                    use_digits=digits_var.get(),
                    use_symbols=symbols_var.get()
                )
                result_entry.delete(0, tk.END)
                result_entry.insert(0, pwd)

                # Show strength rating
                strength = password_gen.evaluate_strength(pwd)
                if strength == "Weak":
                    strength_label.configure(text=f"Strength: {strength} 🔴", text_color=COLORS["error"])
                elif strength == "Medium":
                    strength_label.configure(text=f"Strength: {strength} 🟡", text_color=COLORS["warning"])
                else:
                    strength_label.configure(text=f"Strength: {strength} 🟢", text_color=COLORS["success"])
            except ValueError as e:
                messagebox.showwarning("Invalid Settings", str(e))

        # Action Buttons Layout
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(fill="x", padx=25, pady=(5, 20))
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)

        gen_btn = ctk.CTkButton(
            btn_frame, text="⚡ Generate",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
            fg_color=COLORS["primary"], hover_color=COLORS["primary_hover"],
            text_color=COLORS["text_primary"], height=42,
            corner_radius=8,
            command=do_generate
        )
        gen_btn.grid(row=0, column=0, padx=(0, 6), sticky="ew")

        def copy_to_clipboard():
            pwd = result_entry.get()
            if pwd:
                self.root.clipboard_clear()
                self.root.clipboard_append(pwd)
                messagebox.showinfo("Copied", "Password copied to clipboard!")

        copy_btn = ctk.CTkButton(
            btn_frame, text="📋 Copy",
            font=ctk.CTkFont(family=FONT_FAMILY, size=12, weight="bold"),
            fg_color=COLORS["bg_dark"], hover_color="#334155",
            border_color=COLORS["border"], border_width=1,
            text_color=COLORS["text_primary"], height=42,
            corner_radius=8,
            command=copy_to_clipboard
        )
        copy_btn.grid(row=0, column=1, padx=(6, 0), sticky="ew")

        # Initial password generation
        do_generate()
