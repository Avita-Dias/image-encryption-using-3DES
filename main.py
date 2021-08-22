import tkinter
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox as mb
from PIL import Image, ImageTk
import PIL
from Cryptodome.Cipher import DES3
from hashlib import md5

root = Tk()
root.geometry("480x540")
root.title("image encryption and decryption")


def open_file():
    file1 = filedialog.askopenfile(mode='r', filetype=[('png file', '*.png'), ('jpg file', '*.jpg')])
    if file1 is not None:
        open_file.i = file1.name
        file_name = file1.name
        open_file.f_name = Label(root, text=file_name)
        open_file.f_name.place(x=10, y=70)
        try:
            img = Image.open(file_name)
            img = img.resize((144, 240))
            open_file.tk_image = ImageTk.PhotoImage(img)
            tkinter.Label(root, image=open_file.tk_image).place(x=160, y=100)
        except PIL.UnidentifiedImageError:
            label2 = Label(root, text="skipping unreadable image"). place(x=160, y=100)
    else:
        mb.showerror("upload file", "Sorry, no file has been uploaded")


def encrypt_img():
    if (hasattr(open_file, 'i') == True) and (user_key.get("1.0", END) != "\n"):
        if mb.askyesno('Verify', 'do you want to encrypt the selected image?'):
            filename = open_file.i
            with open(filename, 'rb') as input_file:
                file_bytes = input_file.read()
            new_file_bytes = cipher.encrypt(file_bytes)
            with open(filename, 'wb') as output_file:
                output_file.write(new_file_bytes)
            mb.showinfo("info", "image has been encrypted")
            root.destroy()
        else:
            mb.showinfo('No', 'encryption has been cancelled')
    else:
        mb.showerror("error", "image not uploaded or key missing\nTry again")


def decrypt_img():
    if (hasattr(open_file, 'i') == True) and (user_key.get("1.0", END) != "\n"):
        if mb.askyesno('Verify', 'do you want to decrypt the selected image?'):
            filename = open_file.i
            with open(filename, 'rb') as input_file:
                file_bytes = input_file.read()
            new_file_bytes = cipher.decrypt(file_bytes)
            with open(filename, 'wb') as output_file:
                output_file.write(new_file_bytes)
            mb.showinfo("info", "image has been decrypted")
            root.destroy()
        else:
            mb.showinfo('No', 'decryption has been cancelled')
    else:
        mb.showerror("error", "image not uploaded or key missing\nTry again")


file_upl = Button(root, text="open file", command=open_file)
file_upl.place(x=220, y=20)

label1 = Label(root, text='enter key: ')
label1.place(x=40, y=400)
user_key = Text(root, height=1, width=15)
user_key.place(x=150, y=400)

key = user_key.get("1.0", END)
key_hash = md5(key.encode('ascii')).digest()  # 16-byte key
tripleDES_key = DES3.adjust_key_parity(key_hash)
cipher = DES3.new(tripleDES_key, DES3.MODE_EAX, nonce=b'0')

enc_button = Button(root, text="encrypt", command=encrypt_img)
enc_button.place(x=80, y=470)

dec_button = Button(root, text="decrypt", command=decrypt_img)
dec_button.place(x=300, y=470)

root.mainloop()
