from PIL import Image
import logging
import tkinter as tk
from tkinter import simpledialog, messagebox
import os
import threading

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def search_file(filename, start_dir):
    for root, dirs, files in os.walk(start_dir):
        if filename in files:
            return os.path.join(root, filename)
    return None

def encode_image(image_filename, message, output_label):
    def task():
        try:
            image_path = search_file(image_filename, "C:\\")
            if not image_path:
                raise FileNotFoundError(f"The file {image_filename} does not exist on your computer.")

            logging.info(f"File found at: {image_path}")
            img = Image.open(image_path)
            img = img.convert("RGB")
            width, height = img.size
            pixels = img.load()

            # Convert message to binary
            binary_message = ''.join(format(ord(char), '08b') for char in message)
            binary_message += '1111111111111110'  # End of message delimiter

            message_index = 0
            message_length = len(binary_message)

            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]

                    # Modify red channel
                    if message_index < message_length:
                        r = int(format(r, '08b')[:-1] + binary_message[message_index], 2)
                        message_index += 1

                    # Modify green channel
                    if message_index < message_length:
                        g = int(format(g, '08b')[:-1] + binary_message[message_index], 2)
                        message_index += 1

                    # Modify blue channel
                    if message_index < message_length:
                        b = int(format(b, '08b')[:-1] + binary_message[message_index], 2)
                        message_index += 1

                    pixels[x, y] = (r, g, b)

                    if message_index >= message_length:
                        break
                if message_index >= message_length:
                    break

            output_filename = os.path.join(os.path.dirname(image_path), f"{message}.png")
            img.save(output_filename)
            logging.info(f"Message encoded and saved as {output_filename}")
            output_label.config(text=f"Message encoded and saved as {output_filename}\nDone by Praharsha Kanaparthi")
        except FileNotFoundError as fnf_error:
            logging.error(fnf_error)
            output_label.config(text=f"{str(fnf_error)}\nDone by Praharsha Kanaparthi")
        except Exception as e:
            logging.error(f"Failed to encode image: {str(e)}")
            output_label.config(text=f"Failed to encode image: {str(e)}\nDone by Praharsha Kanaparthi")

    threading.Thread(target=task).start()

def decode_image(image_filename, output_label):
    def task():
        try:
            image_path = search_file(image_filename, "C:\\")
            if not image_path:
                raise FileNotFoundError(f"The file {image_filename} does not exist on your computer.")

            logging.info(f"File found at: {image_path}")
            img = Image.open(image_path)
            img = img.convert("RGB")
            width, height = img.size
            pixels = img.load()

            binary_message = ""
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]

                    binary_message += format(r, '08b')[-1]
                    binary_message += format(g, '08b')[-1]
                    binary_message += format(b, '08b')[-1]

            # Split by 8 bits and convert to characters
            binary_message = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]

            # Convert binary to characters and find end of message delimiter
            decoded_message = ""
            for byte in binary_message:
                decoded_message += chr(int(byte, 2))
                if decoded_message[-2:] == 'þ':  # End of message delimiter
                    break

            logging.info("Message decoded successfully")
            output_label.config(text=f"The decoded message is: {decoded_message[:-2]}\nDone by Praharsha Kanaparthi")
        except FileNotFoundError as fnf_error:
            logging.error(fnf_error)
            output_label.config(text=f"{str(fnf_error)}\nDone by Praharsha Kanaparthi")
        except Exception as e:
            logging.error(f"Failed to decode image: {str(e)}")
            output_label.config(text=f"Failed to decode image: {str(e)}\nDone by Praharsha Kanaparthi")

    threading.Thread(target=task).start()

def prompt_encode_image(output_label):
    image_filename = simpledialog.askstring("Input", "Enter the image file name (including extension):\nDone by Praharsha Kanaparthi")
    if not image_filename:
        return

    message = simpledialog.askstring("Input", "Enter the message to encode (this will also be the output filename):\nDone by Praharsha Kanaparthi")
    if not message:
        return

    encode_image(image_filename, message, output_label)

def prompt_decode_image(output_label):
    image_filename = simpledialog.askstring("Input", "Enter the encoded image file name (including extension):\nDone by Praharsha Kanaparthi")
    if not image_filename:
        return

    decode_image(image_filename, output_label)

# Create the main window
root = tk.Tk()
root.title("Image Steganography - Done by Praharsha Kanaparthi")
root.geometry("400x200")

# Create a label for output messages
output_label = tk.Label(root, text="", wraplength=350)
output_label.pack(pady=10)

# Create buttons for encoding and decoding
encode_button = tk.Button(root, text="Encode Message\nDone by Praharsha Kanaparthi", command=lambda: prompt_encode_image(output_label))
encode_button.pack(pady=10)

decode_button = tk.Button(root, text="Decode Message\nDone by Praharsha Kanaparthi", command=lambda: prompt_decode_image(output_label))
decode_button.pack(pady=10)

# Run the application
root.mainloop()
