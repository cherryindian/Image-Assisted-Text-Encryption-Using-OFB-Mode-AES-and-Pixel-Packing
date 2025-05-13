import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import sys
import base64
import subprocess
from PIL import Image, ImageTk
import io
import math
from random import randint
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Encryption Tool")
        self.root.geometry("800x600")
        self.root.resizable(False, False)

        # Set a nice background color
        self.root.configure(bg="#2c3e50")

        # Create a container frame for all pages
        self.container = tk.Frame(root)
        self.container.pack(fill="both", expand=True)

        # Dictionary to store different frames
        self.frames = {}

        # Create and add all pages to the frames dictionary
        for F in (HomePage, EncryptPage, DecryptPage):
            frame = F(self.container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        # Configure the container to expand with the root window
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        # Show the home page initially
        self.show_frame(HomePage)

    def show_frame(self, page_class):
        """Show the specified frame"""
        frame = self.frames[page_class]
        frame.tkraise()


class BasePage(tk.Frame):
    """Base class for all pages with common styling"""

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.configure(bg="#2c3e50")

        # Create a frame for the header
        self.header_frame = tk.Frame(self, bg="#34495e", height=80)
        self.header_frame.pack(fill="x", padx=10, pady=10)

        # Create a frame for the content
        self.content_frame = tk.Frame(self, bg="#34495e")
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Create a frame for the footer/navigation
        self.footer_frame = tk.Frame(self, bg="#34495e", height=60)
        self.footer_frame.pack(fill="x", padx=10, pady=10)

    def create_button(self, parent, text, command, bg="#3498db", fg="white", width=15):
        """Helper method to create consistent buttons"""
        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            font=("Helvetica", 12, "bold"),
            width=width,
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=5,
            cursor="hand2"
        )
        return button


class HomePage(BasePage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)

        # Configure the header
        title_label = tk.Label(
            self.header_frame,
            text="Secure Encryption Tool",
            font=("Helvetica", 24, "bold"),
            bg="#34495e",
            fg="#ecf0f1"
        )
        title_label.pack(pady=20)

        # Configure the content
        description = tk.Label(
            self.content_frame,
            text="Protect your messages with advanced encryption",
            font=("Helvetica", 14),
            bg="#34495e",
            fg="#ecf0f1",
            wraplength=600,
            justify="center"
        )
        description.pack(pady=20)

        # Create a frame for the main buttons
        buttons_frame = tk.Frame(self.content_frame, bg="#34495e")
        buttons_frame.pack(pady=50)

        # Create buttons for encryption and decryption
        encrypt_button = self.create_button(
            buttons_frame,
            "Encrypt Message",
            lambda: controller.show_frame(EncryptPage),
            bg="#2ecc71",
            width=20
        )
        encrypt_button.grid(row=0, column=0, padx=20, pady=10)

        decrypt_button = self.create_button(
            buttons_frame,
            "Decrypt Message",
            lambda: controller.show_frame(DecryptPage),
            bg="#e74c3c",
            width=20
        )
        decrypt_button.grid(row=0, column=1, padx=20, pady=10)

        # Add exit button to the footer
        exit_button = self.create_button(
            self.footer_frame,
            "Exit",
            lambda: sys.exit(),
            bg="#7f8c8d",
            width=10
        )
        exit_button.pack(side="right", padx=10, pady=10)


class EncryptPage(BasePage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)

        # Configure the header
        title_label = tk.Label(
            self.header_frame,
            text="Encrypt Your Message",
            font=("Helvetica", 24, "bold"),
            bg="#34495e",
            fg="#ecf0f1"
        )
        title_label.pack(pady=20)

        # Configure the content with input fields
        input_frame = tk.Frame(self.content_frame, bg="#34495e")
        input_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Message input
        message_label = tk.Label(
            input_frame,
            text="Enter Your Message:",
            font=("Helvetica", 12),
            bg="#34495e",
            fg="#ecf0f1",
            anchor="w"
        )
        message_label.pack(fill="x", pady=(0, 5))

        self.message_text = scrolledtext.ScrolledText(
            input_frame,
            height=8,
            font=("Helvetica", 12),
            bg="#ecf0f1",
            fg="#2c3e50",
            wrap=tk.WORD
        )
        self.message_text.pack(fill="both", expand=True, pady=(0, 15))

        # Key input
        key_label = tk.Label(
            input_frame,
            text="Enter Encryption Key:",
            font=("Helvetica", 12),
            bg="#34495e",
            fg="#ecf0f1",
            anchor="w"
        )
        key_label.pack(fill="x", pady=(0, 5))

        self.key_entry = tk.Entry(
            input_frame,
            font=("Helvetica", 12),
            bg="#ecf0f1",
            fg="#2c3e50",
            show="*"  # Mask the key input
        )
        self.key_entry.pack(fill="x", pady=(0, 15))

        # Button to encrypt
        encrypt_button = self.create_button(
            input_frame,
            "Encrypt",
            self.encrypt_message,
            bg="#2ecc71",
            width=20
        )
        encrypt_button.pack(pady=10)

        # Navigation buttons in the footer
        home_button = self.create_button(
            self.footer_frame,
            "Home",
            lambda: controller.show_frame(HomePage),
            bg="#3498db",
            width=15
        )
        home_button.pack(side="left", padx=10, pady=10)

        decrypt_button = self.create_button(
            self.footer_frame,
            "Go to Decrypt",
            lambda: controller.show_frame(DecryptPage),
            bg="#e74c3c",
            width=15
        )
        decrypt_button.pack(side="right", padx=10, pady=10)

    def encrypt_message(self):
        """Encrypt the message and save to a file"""
        message = self.message_text.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()

        if not message:
            messagebox.showerror("Error", "Message field is empty!")
            return

        if not key:
            messagebox.showerror("Error", "Key is empty!")
            return

        try:
            # Prepare the key
            key = key.encode('UTF-8')
            key = pad(key, AES.block_size)

            # Convert message to bytes
            pt = bytearray(message.encode('utf-8'))

            # Pack bytes into RGB pixels
            pixels = []
            for i in range(0, len(pt), 3):
                r = pt[i]
                g = pt[i + 1] if i + 1 < len(pt) else 0
                b = pt[i + 2] if i + 2 < len(pt) else 0
                pixels.append((r, g, b))

            # Compute smallest square image to hold all pixels
            side = math.ceil(math.sqrt(len(pixels)))
            img = Image.new('RGB', (side, side), color=(0, 0, 0))
            img_pixels = img.load()

            # Fill image with packed pixels
            idx = 0
            for y in range(side):
                for x in range(side):
                    if idx < len(pixels):
                        img_pixels[x, y] = pixels[idx]
                        idx += 1

            # Save temporary image
            img.save('encryptedImage.png')

            # Encrypt the image
            with open('encryptedImage.png', 'rb') as entry:
                data = entry.read()
                data = pad(data, AES.block_size)
                cipher = AES.new(key, AES.MODE_OFB)
                ciphertext = cipher.encrypt(data)
                iv = b64encode(cipher.iv).decode('UTF-8')
                ciphertext = b64encode(ciphertext).decode('UTF-8')
                to_write = iv + ciphertext

            save_path = filedialog.asksaveasfilename(
                defaultextension=".enc",
                filetypes=[("Encrypted Files", "*.enc")]
            )

            if save_path:
                with open(save_path, 'w') as data_file:
                    data_file.write(to_write)
                messagebox.showinfo("Encryption", "Encryption completed successfully!")
            else:
                messagebox.showwarning("Error", "File save operation canceled!")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during encryption: {str(e)}")


class DecryptPage(BasePage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)

        # Configure the header
        title_label = tk.Label(
            self.header_frame,
            text="Decrypt Your Message",
            font=("Helvetica", 24, "bold"),
            bg="#34495e",
            fg="#ecf0f1"
        )
        title_label.pack(pady=20)

        # Configure the content with input fields
        input_frame = tk.Frame(self.content_frame, bg="#34495e")
        input_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # File selection
        file_frame = tk.Frame(input_frame, bg="#34495e")
        file_frame.pack(fill="x", pady=(0, 15))

        file_label = tk.Label(
            file_frame,
            text="Encrypted File:",
            font=("Helvetica", 12),
            bg="#34495e",
            fg="#ecf0f1",
            anchor="w"
        )
        file_label.pack(side="left", padx=(0, 10))

        self.file_entry = tk.Entry(
            file_frame,
            font=("Helvetica", 12),
            bg="#ecf0f1",
            fg="#2c3e50",
            width=40
        )
        self.file_entry.pack(side="left", padx=(0, 10), fill="x", expand=True)

        browse_button = self.create_button(
            file_frame,
            "Browse",
            self.browse_file,
            bg="#3498db",
            width=10
        )
        browse_button.pack(side="right")

        # Key input
        key_label = tk.Label(
            input_frame,
            text="Enter Decryption Key:",
            font=("Helvetica", 12),
            bg="#34495e",
            fg="#ecf0f1",
            anchor="w"
        )
        key_label.pack(fill="x", pady=(0, 5))

        self.key_entry = tk.Entry(
            input_frame,
            font=("Helvetica", 12),
            bg="#ecf0f1",
            fg="#2c3e50",
            show="*"  # Mask the key input
        )
        self.key_entry.pack(fill="x", pady=(0, 15))

        # Decrypted message output
        result_label = tk.Label(
            input_frame,
            text="Decrypted Message:",
            font=("Helvetica", 12),
            bg="#34495e",
            fg="#ecf0f1",
            anchor="w"
        )
        result_label.pack(fill="x", pady=(0, 5))

        self.result_text = scrolledtext.ScrolledText(
            input_frame,
            height=8,
            font=("Helvetica", 12),
            bg="#ecf0f1",
            fg="#2c3e50",
            wrap=tk.WORD,
            state="disabled"
        )
        self.result_text.pack(fill="both", expand=True, pady=(0, 15))

        # Button frame
        button_frame = tk.Frame(input_frame, bg="#34495e")
        button_frame.pack(fill="x", pady=10)

        # Decrypt button
        decrypt_button = self.create_button(
            button_frame,
            "Decrypt",
            self.decrypt_file,
            bg="#e74c3c",
            width=15
        )
        decrypt_button.pack(side="left", padx=10)

        # Clear button
        clear_button = self.create_button(
            button_frame,
            "Clear Fields",
            self.clear_fields,
            bg="#7f8c8d",
            width=15
        )
        clear_button.pack(side="right", padx=10)

        # Navigation buttons in the footer
        home_button = self.create_button(
            self.footer_frame,
            "Home",
            lambda: controller.show_frame(HomePage),
            bg="#3498db",
            width=15
        )
        home_button.pack(side="left", padx=10, pady=10)

        encrypt_button = self.create_button(
            self.footer_frame,
            "Go to Encrypt",
            lambda: controller.show_frame(EncryptPage),
            bg="#2ecc71",
            width=15
        )
        encrypt_button.pack(side="right", padx=10, pady=10)

    def browse_file(self):
        """Open file dialog to select an encrypted file"""
        filename = filedialog.askopenfilename(
            filetypes=[("Encrypted Files", "*.enc")]
        )
        if filename:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filename)

    def clear_fields(self):
        """Clear all input fields"""
        self.file_entry.delete(0, tk.END)
        self.key_entry.delete(0, tk.END)
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")

    def decrypt_file(self):
        """Decrypt the selected file"""
        filename = self.file_entry.get().strip()
        key = self.key_entry.get().strip()

        if not filename:
            messagebox.showerror("Error", "No file selected!")
            return

        if not key:
            messagebox.showerror("Error", "Key not entered!")
            return

        try:
            key = key.encode('UTF-8')
            key = pad(key, AES.block_size)

            # Read and decrypt the file
            with open(filename, 'r') as entry:
                data = entry.read()
                iv = base64.b64decode(data[:24])
                ciphertext = base64.b64decode(data[24:])
                cipher = AES.new(key, AES.MODE_OFB, iv=iv)
                decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

            # Save the decrypted image temporarily
            with open('decrypted_image.png', 'wb') as out_img:
                out_img.write(decrypted)

            # Load the decrypted image and extract the message
            image = Image.open('decrypted_image.png').convert("RGB")
            width, height = image.size
            pixels = image.load()

            byte_data = bytearray()
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]
                    byte_data.extend([r, g, b])

            # Strip trailing null bytes (0x00) and decode
            message = byte_data.rstrip(b'\x00').decode('utf-8', errors='ignore')

            # Show result in the UI
            self.result_text.config(state="normal")
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert("1.0", message)
            self.result_text.config(state="disabled")

            # Optional: Save the decrypted message to a file
            with open("decryptedMessage.txt", "w") as decrypted_message:
                decrypted_message.write(message)

            messagebox.showinfo("Decryption", "Decryption completed successfully!")

        except (ValueError, KeyError) as e:
            messagebox.showerror("Decryption", "Wrong Key")
            print("Wrong key:", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during decryption: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()