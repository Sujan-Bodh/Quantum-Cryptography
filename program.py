import os
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, Text, END
from tkinter import ttk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image, ImageTk


def derive_aes_key(password: str, salt: bytes, length: int = 32) -> bytes:
    """Derives an AES key from the given password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,  # AES-256 requires a 32-byte key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_aes(key: bytes, plaintext: bytes) -> bytes:
    """Encrypts plaintext using AES with the given key."""
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = iv + encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def decrypt_aes(key: bytes, ciphertext: bytes) -> bytes:
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext

class AESBluetoothApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Quantum Encryption and Bluetooth App")
        self.root.geometry("1000x700")
        self.root.configure(bg="#b0cfde")

        self.selected_file = None
        
       

        # Style settings
        style = ttk.Style()
        style.configure("TLabel", background="#b0cfde", foreground="white", font=("Helvetica", 12))
        style.configure("TButton", font=("Helvetica", 12, "bold"), padding=10)
        style.map("TButton", background=[("active", "#2980b9"), ("pressed", "#1abc9c")])  # Active/pressed colors
        style.configure("TButton", borderwidth=2, relief="raised")

        # Title Label
        title_label = ttk.Label(root, text="QUANTUM CRYPTOGRAPHY", font=("Helvetica", 18, "bold"))
        title_label.pack(pady=10)

        # Shared Key Entry
        self.shared_key_label = ttk.Label(root, text="Enter Shared Key:", font=("Helvetica", 12,"bold"))
        self.shared_key_label.pack(pady=5)

        self.shared_key_entry = ttk.Entry(root, width=50, show='*')
        self.shared_key_entry.pack(pady=5)
        # Text Box
        self.text_box = Text(root, height=20, width=120, font=("Courier", 11), wrap="word", bg="white", fg="black")
        self.text_box.pack(pady=10)

        # Buttons with ttk Styling
        button_frame = ttk.Frame(root)
        button_frame.pack(pady=5)

        self.load_button = ttk.Button(button_frame, text="Select File",command=self.select_file)
        self.load_button.grid(row=0, column=0, padx=10)

        self.encrypt_button = ttk.Button(button_frame, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.grid(row=0, column=1, padx=10)

        self.decrypt_button = ttk.Button(button_frame, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.grid(row=0, column=2, padx=10)

        self.send_button = ttk.Button(button_frame, text="Send via Bluetooth", command=self.select_and_send_file)
        self.send_button.grid(row=0, column=3, padx=10)

        self.receive_button = ttk.Button(button_frame, text="Receive via Bluetooth", command=self.receive_files)
        self.receive_button.grid(row=0, column=4, padx=10)

        # Status Label
        self.status_label = ttk.Label(root, text="", foreground="#b0cfde")
        self.status_label.pack(pady=10)

        # Footer label for additional information
        footer_label = ttk.Label(root, text="Quantum Encryption App - Secure your data", font=("Helvetica", 10), foreground="white")
        footer_label.pack(side="bottom", pady=5)

    def select_file(self):
        self.selected_file = filedialog.askopenfilename()
        if self.selected_file:
            self.status_label.config(text=f"Selected: {self.selected_file}")

    def encrypt_file(self):
        if self.selected_file:
            shared_key = self.shared_key_entry.get()
            if not shared_key:
                messagebox.showwarning("Warning", "Please enter a shared key.")
                return
            
            salt = os.urandom(16)  # Random salt for demonstration, save it alongside the encrypted file
            key = derive_aes_key(shared_key, salt)
            with open(self.selected_file, "rb") as file:
                plaintext = file.read()
            ciphertext = encrypt_aes(key, plaintext)
            with open(self.selected_file + ".aes", "wb") as file:
                file.write(salt + ciphertext)  # Save salt + ciphertext
            messagebox.showinfo("Success", f"File {self.selected_file} encrypted successfully!")

    def decrypt_file(self):
        if self.selected_file:
            with open(self.selected_file, "rb") as file:
                salt = file.read(16)  # Read salt
                ciphertext = file.read()
                shared_key = self.shared_key_entry.get()
                if not shared_key:
                    messagebox.showwarning("Warning", "Please enter a shared key.")
                    return
                
                key = derive_aes_key(shared_key, salt)
                plaintext = decrypt_aes(key, ciphertext)

                if self.selected_file.endswith('.aes'):
                    original_file = self.selected_file[:-4]  # Remove .aes extension
                    with open(original_file, "wb") as file:
                        file.write(plaintext)
                    self.show_data(original_file)
                    messagebox.showinfo("Success", f"File {self.selected_file} decrypted successfully!")

    def show_data(self, file_path):
        if file_path.endswith('.txt'):
            with open(file_path, 'r') as file:
                data = file.read()
                self.text_box.delete(1.0, END)
                self.text_box.insert(END, data)

        elif file_path.endswith(('.png', '.jpg', '.jpeg', '.gif')):
            self.display_image(file_path)

        elif file_path.endswith(('.mp3', '.wav')):
            self.play_audio(file_path)

        elif file_path.endswith(('.mp4', '.avi')):
            self.play_video(file_path)

    def display_image(self, image_path):
        img = Image.open(image_path)
        img.thumbnail((400, 400))  # Resize for display
        img = ImageTk.PhotoImage(img)
       
        # Create a new top-level window to display the image
        img_window = tk.Toplevel(self.root)
        img_label = tk.Label(img_window, image=img)
        img_label.image = img  # Keep a reference to avoid garbage collection
        img_label.pack()

    def play_audio(self, audio_path):
        pygame.mixer.init()
        pygame.mixer.music.load(audio_path)
        pygame.mixer.music.play()
        messagebox.showinfo("Playing Audio", f"Now playing: {audio_path}")

    def play_video(self, video_path):
        cap = cv2.VideoCapture(video_path)
        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break
            cv2.imshow("Video", frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):  # Press 'q' to exit
                break
        cap.release()
        cv2.destroyAllWindows()

    def select_and_send_file(self):
        # Open a dialog to select the file to send
        if not self.selected_file:
            messagebox.showinfo("No file selected", "Please select a file to send.")
            return
        
        try:
            subprocess.Popen(["fsquirt"])
            messagebox.showinfo("Bluetooth Transfer", "The Bluetooth file transfer wizard has been opened. Please follow the on-screen instructions to complete the transfer.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def receive_files(self):
        # Launch the Windows Bluetooth file transfer wizard for receiving files
        try:
            subprocess.Popen(["fsquirt", "/receive"])  # Use the receive option
            messagebox.showinfo("Bluetooth Receive", "The Bluetooth file transfer wizard for receiving files has been opened.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AESBluetoothApp(root)
    root.mainloop()
