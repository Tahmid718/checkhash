#!/usr/bin/env python

import hashlib
import tkinter as tk
import threading
import os

from tkinter import filedialog, messagebox

algorithms = [
    "MD5",
    "SHA1",
    "SHA2/SHA256"
]

class hash:
    def __init__(self):
        self.filepath = None

    def browse(self):
        filepath = filedialog.askopenfilename(initialdir="/", title="Select a file.")

        fpestr.set(filepath)
        HSE.delete(0, tk.END)

    def start_digest_thread(self):
        filepath = fpestr.get()

        if os.path.exists(filepath):
            if os.path.getsize(fpestr.get()) > 2 * (1024 ** 3):
                ANS = messagebox.askokcancel(title="Hash Check", message="The file is too large. Processing the file to check hash might destablize the computer. Do you still want to process?")
                if ANS:
                    t = threading.Thread(target=self.digest, args=(filepath,))
                    t.start()
            else:
                t = threading.Thread(target=self.digest, args=(filepath,))
                t.start()
        else:
            messagebox.showerror(title="Hash Check", message="Invalid File.")
    
    def digest(self, filepath: str):
        hashtype = hashstr.get()

        OPF.config(state='disabled')
        OPT.config(state='disabled')
        CKH.config(state='disabled')
        CHB.config(state='disabled')

        root.title("Hash Checksum | Wait the file is being processed..")

        cntn = open(filepath, 'rb').read()

        root.title("Hash Checksum | Calculating Hash...")

        if hashtype == "MD5":
            checksumhash = hashlib.md5(cntn).hexdigest()
        elif hashtype == "SHA1":
            checksumhash = hashlib.sha1(cntn).hexdigest()
        else:
            checksumhash = hashlib.sha256(cntn).hexdigest()

        root.title("Hash Checksum")

        hashent.set(checksumhash)

        CHE.config(state='normal')
        CHB.config(state='normal')
        OPF.config(state='normal')
        OPT.config(state='normal')
        CKH.config(state='normal')
        CHB.config(state='normal')

    def verify(self):
        userhash = CHE.get().strip()
        realhash = hashent.get()

        if realhash == userhash:
            messagebox.showinfo(title="Hash Check", message="Hash matches.")
        else:
            messagebox.showerror(title="Hash Check Error", message="Hash does not match!")

#! Gui
root = tk.Tk()

fpestr = tk.StringVar()
hashstr = tk.StringVar()
hashent = tk.StringVar()

hashstr.set("MD5")

root.title("Hash Checksum")
root.geometry("800x500")
root.resizable(0,0)
root.iconbitmap('hash-tag.ico')

tk.Label(root, text="Enter the file which you wanna check.", font=('Arial', 15)).place(x=40, y=55)

OPF = tk.Button(root, text="Open file", font=('Arial', 12), command=hash().browse)
OPF.place(x=400, y=55, width=80, height=30)

tk.Label(root, text="File:", font=('Arial', 14)).place(x=40, y=135)

tk.Entry(root, state='readonly', width=60, font=('Arial', 12), textvariable=fpestr).place(x=95, y=141)

tk.Label(root, text="Algorithm:", font=('Arial', 15)).place(x=40, y=197)

OPT = tk.OptionMenu(root, hashstr, *algorithms)
OPT.config(font=('Arial', 12))
OPT.place(x=140, y=195)

CKH = tk.Button(root, text="Check hash", font=('Arial', 12), command=hash().start_digest_thread)
CKH.place(x=310, y=195)

tk.Label(root, text="Hash:", font=('Arial', 15)).place(x=40, y=300)

HSE = tk.Entry(root, state='readonly', font=('Arial', 12), textvariable=hashent, width=60)
HSE.place(x=100, y=305)

tk.Label(root, text="Easily check the hash right or not.", font=('Arial', 9)).place(x=40,y=365)

tk.Label(root, text="Check hash:", font=('Arial', 15)).place(x=40, y=395)

CHE = tk.Entry(root, state='disabled', font=('Arial', 12), width=60)
CHE.place(x=170, y=395)

CHB = tk.Button(root, state='disabled', text='Verify', font=('Arial', 13), command=hash().verify)
CHB.place(x=40, y=435)

root.mainloop()
