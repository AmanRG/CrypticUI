import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import pyperclip

# Initialize a random encryption key
def generate_key():
    key = Fernet.generate_key()
    key_entry.delete(0, tk.END)
    key_entry.insert(0, key.decode())

# Encrypt text using a given key
def encrypt_text():
    key = key_entry.get().encode()
    text = input_text.get("1.0", "end-1c")
    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(text.encode())
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, encrypted_text.decode())
    pyperclip.copy(encrypted_text.decode())

# Decrypt text using a given key
def decrypt_text():
    key = key_entry.get().encode()
    encrypted_text = input_text.get("1.0", "end-1c")
    cipher_suite = Fernet(key)
    try:
        decrypted_text = cipher_suite.decrypt(encrypted_text.encode())
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted_text.decode())
        pyperclip.copy(decrypted_text.decode())
    except:
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, "Decryption error. Invalid key or input.")

# Function to encode text into an image
def encode_image():
    image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg;*.jpeg;*.png;*.gif")])
    if image_path:
        original_image = Image.open(image_path)
        text = input_text.get("1.0", "end-1c")
        encoded_image = hide_text_in_image(original_image, text)
        img = ImageTk.PhotoImage(encoded_image)
        output_label.config(image=img)
        output_label.image = img
        encoded_image.save("encoded_image.png")  # Save the encoded image

        # Enable the Download Encoded Image button
        download_button.config(state="normal")

# Function to hide text within an image
def hide_text_in_image(image, text):
    encoded_image = image.copy()
    binary_text = ''.join(format(ord(char), '08b') for char in text)
    binary_text += "1111111111111110"  # Add a delimiter to signal the end of the message

    index = 0
    width, height = encoded_image.size

    for y in range(height):
        for x in range(width):
            pixel = list(encoded_image.getpixel((x, y)))
            for color_channel in range(3):
                if index < len(binary_text):
                    pixel[color_channel] = pixel[color_channel] & ~1 | int(binary_text[index])
                    index += 1
            encoded_image.putpixel((x, y), tuple(pixel))

    return encoded_image

# Function to decode text from an image
def decode_image():
    image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg;*.jpeg;*.png;*.gif")])
    if image_path:
        encoded_image = Image.open(image_path)
        decoded_text = extract_text_from_image(encoded_image)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decoded_text)

# Function to extract text from an image
def extract_text_from_image(image):
    binary_text = ""
    width, height = image.size
    delimiter = "1111111111111110"  # Delimiter to signal the end of the message
    delimiter_index = 0

    for y in range(height):
        for x in range(width):
            pixel = image.getpixel((x, y))
            for color_channel in pixel:
                binary_text += str(color_channel & 1)

                # Check for the delimiter at the end
                if delimiter_index < len(delimiter) and binary_text.endswith(delimiter):
                    delimiter_index += 1

                # If we have found the delimiter, stop processing
                if delimiter_index == len(delimiter):
                    binary_text = binary_text[:-len(delimiter)]  # Remove the delimiter
                    text = ''.join([chr(int(binary_text[i:i+8], 2)) for i in range(0, len(binary_text), 8)])
                    return text

# Function to download the encoded image
def download_encoded_image():
    file_dialog = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Files", "*.png")])
    if file_dialog:
        Image.open("encoded_image.png").save(file_dialog)

# Create the main GUI window
app = tk.Tk()
app.title("CrypticUI")
app.geometry("800x600")
app.configure(bg='#D3BFE1')  # Set background color to lilac

# Style for widgets
style = ttk.Style()
style.configure('TButton', font=('Helvetica', 12), padding=5, background='#007ACC', foreground='black')
style.configure('TLabel', font=('Helvetica', 14), background='#D3BFE1')  # Background color changed to lilac
style.configure('TEntry', font=('Helvetica', 14))
style.configure('TText', font=('Helvetica', 14))

# Heading and Subheading
heading_label = ttk.Label(app, text="CrypticUI", font=('Helvetica', 24, 'bold'), background='#D3BFE1')
subheading_label = ttk.Label(app, text="Developed by Zav Zav Nation", font=('Helvetica', 18), background='#D3BFE1')
heading_label.pack(pady=10)
subheading_label.pack()

# Key input
key_frame = tk.Frame(app, bg='#D3BFE1')  # Frame background color
key_label = ttk.Label(key_frame, text="Encryption Key:")
key_entry = ttk.Entry(key_frame)
generate_key_button = ttk.Button(key_frame, text="Generate Key", command=generate_key)
key_label.pack(side="left", anchor="w")  # Left align label
key_entry.pack(side="left", fill="x", expand=True)  # Center align entry
generate_key_button.pack(side="right", anchor="e", padx=10, pady=20)  # Right align button
key_frame.pack(fill="x")

# Input and output text areas
input_label = ttk.Label(app, text="Input Text:", background='#D3BFE1')
input_text = tk.Text(app, height=3, width=60, font=('Helvetica', 14))
input_label.pack(pady=5)
input_text.pack()

output_label = ttk.Label(app, text="Output Text:", background='#D3BFE1')
output_text = tk.Text(app, height=3, width=60, font=('Helvetica', 14))
output_label.pack(pady=5)
output_text.pack()

# Image display
output_label = ttk.Label(app, text="Encoded/Decoded Image:")
output_label.pack(pady=10)

# Buttons for encryption and decryption
encrypt_button = ttk.Button(app, text="Encrypt Text", command=encrypt_text)
decrypt_button = ttk.Button(app, text="Decrypt Text", command=decrypt_text)
encode_image_button = ttk.Button(app, text="Encode Image", command=encode_image)
decode_image_button = ttk.Button(app, text="Decode Image", command=decode_image)
encrypt_button.pack(pady=5)
decrypt_button.pack(pady=5)
encode_image_button.pack(pady=5)
decode_image_button.pack(pady=5)

# Copy button for output
copy_button = ttk.Button(app, text="Copy Output", command=lambda: pyperclip.copy(output_text.get("1.0", "end-1c")))
copy_button.pack(pady=10)

# Download button for encoded image
download_button = ttk.Button(app, text="Download Encoded Image", command=download_encoded_image, state="disabled")
download_button.pack(pady=10)

app.mainloop()
