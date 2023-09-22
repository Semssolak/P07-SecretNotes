from tkinter import *
from PIL import Image, ImageTk
from tkinter import messagebox  # uyarı mesajı için
import base64  #encryption için

def encode(key, clear):  # internetten hazır aldık şifreleme
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):  # şifre çözme
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
        #encryption
        message_encrpted = encode(master_secret,message)
        try:
            with open("mysecret.txt",mode="a") as textfile:
                textfile.write(f"\n{title}\n{message_encrpted}")  #dosyaya şifrelenmiş halini koyduk
        except FileNotFoundError:
            with open("mysecret.txt",mode="w") as textfile:  # sadece bu kısımlada kullanabilirdik
                textfile.write(f"\n{title}\n{message_encrpted}")   #fakat bazen hata alabiliriz
        finally:  # buttona a bastığımızda ekranda yazı kalmaması için
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
            secret_text.insert("1.0",decrypted_message) #bu alana decrypte edilmiş halini ekledik
        except:
            messagebox.showinfo(title="!Error",message="Please enter encrypted text!")

#UI
window = Tk()
window.title("Secret Notes")
window.minsize(width=500, height=700)
window.config(background="#3C4D98")

#Icon
icon = PhotoImage(file='Secret_Note.png')
window.iconphoto(False, icon)

#Image
# PIL ile resmi açın
img = Image.open("Secret_Note.png")
# Yeni boyutları belirleyin
new_width = 300
new_height = 200
# Görüntüyü yeniden boyutlandırın
img = img.resize((new_width, new_height))
# Tkinter için uygun bir formata dönüştürün
tk_img = ImageTk.PhotoImage(img)
# Label kullanarak görüntüyü gösterin
label = Label(window, image=tk_img)
label.grid(row=0, column=3, padx=30, pady=5)
label.config(background="#3C4D98")

#photo = PhotoImage(file ="")
#photo_label = Label(image=photo)
#photo_label.pack()   #beu şekilde de foto koyabiliriz fakat biz resize yapmak istedik

# yada canvasla boş bir alan oluşturup yapılabilir
#canvas = Canvas(height=200,width=200)
#canvas.create_image(0,0,image=photo)  # kooridnat
#canvas.pack()


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
