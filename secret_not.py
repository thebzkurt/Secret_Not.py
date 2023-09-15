import tkinter as tk
from tkinter import ttk
from PIL import ImageTk, Image
from tkinter import messagebox
from tkinter import END
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key [i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save():
    title = Tatile_entry.get()
    text = Secret_text.get("1.0",END)
    key = Key_entry.get()

    if len(title) == 0 or len(text) == 0 or len(key) == 0:
        messagebox.showinfo(title="Error", message="Please enter all info")
    else:
        encrypted_mes = encode(key,text)

        try:
            with open("secret.txt","a") as data_file:
                data_file.write(f"\n{title}\n{encrypted_mes}")
        except FileNotFoundError:
            with open("secret.txt","a") as data_file:
                data_file.write(f"\n{title}\n{encrypted_mes}")
        finally:
            Tatile_entry.delete(0,END)
            Secret_text.delete("1.0",END)
            Key_entry.delete(0,END)

def decrypt_notes():
    text_encrypted = Secret_text.get("1.0",END)
    key_encrypted = Key_entry.get()

    if len(text_encrypted) == 0 or len(key_encrypted) == 0:
        messagebox.showinfo(title="Erro!!",message="Please enter all info.")
    else:
        try:
            dencrypted_mes = decode(key_encrypted, text_encrypted)
            Secret_text.delete("1.0",END)
            Secret_text.insert("1.0",dencrypted_mes)
        except:
            messagebox.showinfo(title="Erro!!", message="Pleas enter encryped text !")

root = tk.Tk()
root.geometry("500x500")
root.title("Sectet Not")

Tatile_label = tk.Label(
    text="Enter your title",
    font= ("Courier", 12)
    )
Secret_label = tk.Label(
    text="Entre your secret", 
    font= ("Courier", 12)
    )
Key_label = tk.Label(
    text="Entre your key", 
    font=("Courier",12)
    )


Secret_text = tk.Text(
    root,
    width=40,
    height=10
    )
Tatile_entry = tk.Entry(
    root,
    width=40 
    )
Key_entry = tk.Entry(
    root,
     width=40
    )

Save_Encrypt = tk.Button(
    text="Save and Encrypt",
    command= save
    )
Decrypt = tk.Button(
    text="Decrypt",
    borderwidth=2,
    command=decrypt_notes
    )


image = Image.open("secret.jpg")
resize_image = image.resize((120,120))
img = ImageTk.PhotoImage(resize_image)
img_label = tk.Label(
    image=img
    )





























img_label.pack()
Tatile_label.pack()
Tatile_entry.pack()
Secret_label.pack()
Secret_text.pack()
Key_label.pack()
Key_entry.pack()
Save_Encrypt.pack()
Decrypt.pack()

root.mainloop()