import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, PhotoImage
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from cryptography.fernet import Fernet
import os

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    username = Column(String, primary_key=True)
    password = Column(String, nullable=False)

class Password(Base):
    __tablename__ = 'passwords'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, nullable=False)
    platform = Column(String)
    password = Column(String, nullable=False)
    owner_username = Column(String, ForeignKey('users.username'), nullable=False)

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("800x600")
        self.root.config(bg='#ffccbc')

        # Load or generate encryption key
        self.key_file = "key.key"
        self.encryption_key = self.load_key()

        self.current_user = None

        # Set up database
        #change this to connect online
        self.engine = create_engine('sqlite:///password_manager.db')
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()

        self.frames = {}
        container = tk.Frame(self.root, bg='#ffccbc')
        container.pack(fill='both', expand=True)

        self.create_frames(container)
        self.show_frame("LoginPage")

        # Handle the window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def load_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as key_file:
                return key_file.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as key_file:
                key_file.write(key)
            return key

    def encrypt_password(self, password):
        cipher_suite = Fernet(self.encryption_key)
        return cipher_suite.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        cipher_suite = Fernet(self.encryption_key)
        return cipher_suite.decrypt(encrypted_password.encode()).decode()

    def create_frames(self, container):
        for F in (LoginPage, SignupPage, PasswordManagerPage):
            frame = F(parent=container, controller=self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky='nsew')

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()

    def add_user(self, username, password):
        new_user = User(username=username, password=password)
        self.session.add(new_user)
        self.session.commit()

    def get_user(self, username):
        return self.session.query(User).filter_by(username=username).first()

    def add_password(self, username, platform, password, owner):
        encrypted_password = self.encrypt_password(password)
        new_password = Password(username=username, platform=platform, password=encrypted_password, owner_username=owner)
        self.session.add(new_password)
        self.session.commit()

    def get_passwords(self, owner):
        return self.session.query(Password).filter_by(owner_username=owner).all()

    def update_password(self, id, username, platform, password):
        encrypted_password = self.encrypt_password(password)
        password_entry = self.session.query(Password).filter_by(id=id).first()
        password_entry.username = username
        password_entry.platform = platform
        password_entry.password = encrypted_password
        self.session.commit()

    def delete_password(self, id):
        password_entry = self.session.query(Password).filter_by(id=id).first()
        self.session.delete(password_entry)
        self.session.commit()

    def close(self):
        self.session.close()

    def on_closing(self):
        self.close()
        self.root.quit()

class LoginPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg='#ffccbc')
        self.controller = controller

        title_font = ("Helvetica", 16, "bold")
        label_font = ("Helvetica", 12)
        button_font = ("Helvetica", 12)

        ttk.Label(self, text="Login", font=title_font, background='#ffccbc').pack(pady=20)

        self.username_label = ttk.Label(self, text="Username:", font=label_font, background='#ffccbc')
        self.username_label.pack(pady=5)

        self.username_entry = ttk.Entry(self, font=label_font)
        self.username_entry.pack(pady=5)

        self.password_label = ttk.Label(self, text="Password:", font=label_font, background='#ffccbc')
        self.password_label.pack(pady=5)

        self.password_entry = ttk.Entry(self, show='*', font=label_font)
        self.password_entry.pack(pady=5)

        ttk.Button(self, text="Login", command=self.login, style='TButton').pack(pady=10)
        ttk.Button(self, text="Sign Up", command=lambda: controller.show_frame("SignupPage"), style='TButton').pack(pady=10)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        user = self.controller.get_user(username)

        if user and user.password == password:
            self.controller.current_user = username
            self.controller.show_frame("PasswordManagerPage")
        else:
            messagebox.showerror("Error", "Invalid username or password.")

class SignupPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg='#ffccbc')
        self.controller = controller

        title_font = ("Helvetica", 16, "bold")
        label_font = ("Helvetica", 12)
        button_font = ("Helvetica", 12)

        ttk.Label(self, text="Sign Up", font=title_font, background='#ffccbc').pack(pady=20)

        self.username_label = ttk.Label(self, text="Username:", font=label_font, background='#ffccbc')
        self.username_label.pack(pady=5)

        self.username_entry = ttk.Entry(self, font=label_font)
        self.username_entry.pack(pady=5)

        self.password_label = ttk.Label(self, text="Password:", font=label_font, background='#ffccbc')
        self.password_label.pack(pady=5)

        self.password_entry = ttk.Entry(self, show='*', font=label_font)
        self.password_entry.pack(pady=5)

        ttk.Button(self, text="Sign Up", command=self.sign_up, style='TButton').pack(pady=10)
        ttk.Button(self, text="Back to Login", command=lambda: controller.show_frame("LoginPage"), style='TButton').pack(pady=10)

    def sign_up(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Username and password are required.")
            return

        if self.controller.get_user(username):
            messagebox.showerror("Error", "Username already exists.")
        else:
            self.controller.add_user(username, password)
            messagebox.showinfo("Success", "Account created successfully!")
            self.controller.show_frame("LoginPage")

class PasswordManagerPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg='#ffccbc')
        self.controller = controller

        # Styling
        title_font = ("Helvetica", 16, "bold")
        label_font = ("Helvetica", 12)
        button_font = ("Helvetica", 12)

        ttk.Label(self, text="Password Manager", font=title_font, background='#ffccbc').pack(pady=20)

        # Left Frame for Listing and Deleting Passwords
        left_frame = tk.Frame(self, bg='#ffccbc')
        left_frame.pack(side='left', fill='both', expand=True, padx=10, pady=10)

        ttk.Label(left_frame, text="List of Passwords", font=label_font, background='#ffccbc').pack(pady=10)

        self.password_listbox = tk.Listbox(left_frame, selectmode='multiple', width=60, height=20, bg='#fff')
        self.password_listbox.pack(pady=10)

        ttk.Button(left_frame, text="Delete Selected", command=self.delete_selected, style='TButton').pack(pady=10)

        # Right Frame for Adding and Editing Passwords
        right_frame = tk.Frame(self, bg='#ffccbc')
        right_frame.pack(side='right', fill='both', expand=True, padx=10, pady=10)

        ttk.Label(right_frame, text="Add/Edit Password", font=title_font, background='#ffccbc').pack(pady=20)

        self.username_label = ttk.Label(right_frame, text="Username:", font=label_font, background='#ffccbc')
        self.username_label.pack(pady=5)

        self.username_entry = ttk.Entry(right_frame, font=label_font)
        self.username_entry.pack(pady=5)

        self.platform_label = ttk.Label(right_frame, text="Platform (optional):", font=label_font, background='#ffccbc')
        self.platform_label.pack(pady=5)

        self.platform_entry = ttk.Entry(right_frame, font=label_font)
        self.platform_entry.pack(pady=5)

        self.password_label = ttk.Label(right_frame, text="Password:", font=label_font, background='#ffccbc')
        self.password_label.pack(pady=5)

        self.password_entry = ttk.Entry(right_frame, show='*', font=label_font)
        self.password_entry.pack(pady=5)

        # Eye Icon Button for Show/Hide Password
        self.eye_icon_open = tk.PhotoImage(file="eye_icon_open.png")
        self.eye_icon_closed = tk.PhotoImage(file="eye_icon_closed.png")
        self.eye_button = tk.Button(right_frame, image=self.eye_icon_closed, command=self.toggle_password_visibility, bg='#ffccbc', bd=0)
        self.eye_button.pack(pady=5)

        ttk.Button(right_frame, text="Add Password", command=self.add_password, style='TButton').pack(pady=10)
        ttk.Button(right_frame, text="Edit Password", command=self.edit_password, style='TButton').pack(pady=10)

        # Sign Out and Refresh Buttons
        ttk.Button(right_frame, text="Sign Out", command=self.sign_out, style='TButton').pack(pady=10)
        ttk.Button(right_frame, text="Refresh", command=self.refresh_password_list, style='TButton').pack(pady=10)

        # Password Visibility Tracking
        self.visible_passwords = {}

        # Populate Listbox
        
        self.refresh_password_list()


    def sign_out(self):
        self.controller.current_user = None
        self.controller.show_frame("LoginPage")

    def toggle_password_visibility(self):
        selected_indices = self.password_listbox.curselection()
        if not selected_indices:
            messagebox.showerror("Error", "Select a password to show.")
            return

        entries = self.controller.get_passwords(self.controller.current_user)
        for index in selected_indices:
            if index not in self.visible_passwords:
                self.visible_passwords[index] = False

            # Toggle visibility
            self.visible_passwords[index] = not self.visible_passwords[index]

            # Update Listbox display
            entry = entries[index]
            if self.visible_passwords[index]:
                display_text = f"{entry.username} - {entry.platform} - {self.controller.decrypt_password(entry.password)}"
                self.eye_button.config(image=self.eye_icon_open)
            else:
                display_text = f"{entry.username} - {entry.platform} - {'*' * len(self.controller.decrypt_password(entry.password))}"
                self.eye_button.config(image=self.eye_icon_closed)

            self.password_listbox.delete(index)
            self.password_listbox.insert(index, display_text)

    def refresh_password_list(self):
        self.password_listbox.delete(0, tk.END)
        entries = self.controller.get_passwords(self.controller.current_user)
        self.visible_passwords = {}
        for idx, entry in enumerate(entries):
            display_text = f"{entry.username} - {entry.platform} - {'*' * len(self.controller.decrypt_password(entry.password))}"
            self.password_listbox.insert(tk.END, display_text)
            self.visible_passwords[idx] = False

    def add_password(self):
        username = self.username_entry.get()
        platform = self.platform_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Username and password are required.")
            return

        self.controller.add_password(username, platform, password, self.controller.current_user)
        messagebox.showinfo("Success", "Password added successfully!")
        self.refresh_password_list()
        self.clear_entries()

    def edit_password(self):
        selected_indices = self.password_listbox.curselection()
        if not selected_indices:
            messagebox.showerror("Error", "Select a password to edit.")
            return

        selected_index = selected_indices[0]
        entries = self.controller.get_passwords(self.controller.current_user)
        entry = entries[selected_index]

        username = self.username_entry.get()
        platform = self.platform_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Username and password are required.")
            return

        self.controller.update_password(entry.id, username, platform, password)
        messagebox.showinfo("Success", "Password updated successfully!")
        self.refresh_password_list()
        self.clear_entries()

    def delete_selected(self):
        selected_indices = self.password_listbox.curselection()
        if not selected_indices:
            messagebox.showerror("Error", "Select passwords to delete.")
            return

        for index in selected_indices:
            entry = self.controller.get_passwords(self.controller.current_user)[index]
            self.controller.delete_password(entry.id)

        messagebox.showinfo("Success", "Selected passwords deleted successfully!")
        self.refresh_password_list()

    def clear_entries(self):
        self.username_entry.delete(0, tk.END)
        self.platform_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    root.iconbitmap("safe.ico")
    app = PasswordManagerApp(root)
    root.mainloop()
