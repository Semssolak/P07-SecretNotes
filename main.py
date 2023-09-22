from tkinter import *
from PIL import Image, ImageTk
from tkinter import messagebox  
import base64  

def encode(key, clear):  
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
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


def encrypt_func():
    title = title_entry.get()
    message = secret_text.get("1.0",END)
    master_secret = key_entry.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!",message="Please enter all info.")
    else:
        message_encrpted = encode(master_secret,message)
        try:
            with open("mysecret.txt",mode="a") as textfile:
                textfile.write(f"\n{title}\n{message_encrpted}") 
        except FileNotFoundError:
            with open("mysecret.txt",mode="w") as textfile:  
                textfile.write(f"\n{title}\n{message_encrpted}") 
        finally: 
            title_entry.delete(0,END)
            key_entry.delete(0,END)
            secret_text.delete("1.0",END)

def decrypt_func():
    message_encrypted = secret_text.get("1.0",END)
    key_text = key_entry.get()

    if len(message_encrypted) == 0 or len(key_text) == 0:
        messagebox.showinfo(title="Error!",message="Please enter all info.")
    else:
        try:
            decrypted_message = decode(key_text,message_encrypted)
            secret_text.delete("1.0",END)
            secret_text.insert("1.0",decrypted_message)
        except:
            messagebox.showinfo(title="!Error",message="Please enter encrypted text!")

window = Tk()
window.title("Secret Notes")
window.minsize(width=500, height=700)
window.config(background="#3C4D98")

icon = PhotoImage(file='Secret_Note.png')
window.iconphoto(False, icon)


img = Image.open("Secret_Note.png")
new_width = 300
new_height = 20
img = img.resize((new_width, new_height))
tk_img = ImageTk.PhotoImage(img)
label = Label(window, image=tk_img)
label.grid(row=0, column=3, padx=30, pady=5)
label.config(background="#3C4D98")

title_label = Label(text="Enter your title",font=("Verdena",10,"normal"))
title_label.grid(row=5, column=3, padx=30, pady=5)
title_label.config(background="#3C4D98")

title_entry = Entry(width=50)
title_entry.grid(row=7,column=3,padx=30,pady=5)
title_entry.config(background="black",foreground="white")

secret_label = Label(text="Enter your secret",font=("Verdena",10,"normal"))
secret_label.grid(row=9, column=3, padx=30, pady=5)
secret_label.config(background="#3C4D98")

secret_text = Text(width=50,height=15)
secret_text.grid(row=11, column=3, padx=30, pady=5)
secret_text.config(background="black",foreground="white")

key_label = Label(text="Enter your master key",font=("Verdena",10,"normal"))
key_label.grid(row=13, column=3, padx=30, pady=5)
key_label.config(background="#3C4D98")

key_entry = Entry(width=50)
key_entry.grid(row=15,column=3,padx=30,pady=5)
key_entry.config(background="black",foreground="white")

save_button = Button(text="Save & Encrypt",command=encrypt_func)
save_button.grid(row=17,column=3,padx=30,pady=5)
save_button.config(background="black",foreground="white")

decrypt_button = Button(text="Decrypt",command=decrypt_func)
decrypt_button.grid(row=19,column=3,padx=30,pady=5)
decrypt_button.config(background="black",foreground="white")

window.mainloop()
