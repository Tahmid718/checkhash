#!/usr/bin/env python

import hashlib
import tkinter as tk

from tkinter import filedialog, messagebox

algorithms = [
    "MD5",
    "SHA1",
    "SHA256"
]

class hash:
    def __init__(self):
        self.hashtype = None
        self.filepath = None
    
    def browse(self):
        filepath = filedialog.askopenfilename(initialdir="/", title="Select a file.")
        self.filepath = filepath
        fpestr.set(self.filepath)
    
    def digest(self):
        self.hashtype = hashstr.get()
        self.filepath = fpestr.get()

        try:
            filebin = open(self.filepath, "rb").read()

            if self.hashtype == "MD5":
                checksumhash = hashlib.md5(filebin).hexdigest()
            elif self.hashtype == "SHA1":
                checksumhash = hashlib.sha1(filebin).hexdigest()
            else:
                checksumhash = hashlib.sha256(filebin).hexdigest()

            hashent.set(checksumhash)

            CHE.config(state='normal')
            CHB.config(state='normal')

        except FileNotFoundError:
            messagebox.showerror(title="Hash Check Error.", message="Choose a file.")

    def verify(self):
        userhash = CHE.get()
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

SFL = tk.Label(root, text="Enter the file which you wanna check.", font=('Arial', 15))
SFL.place(x=40, y=55)

SFB = tk.Button(root, text="Open file", font=('Arial', 12), command=hash().browse)
SFB.place(x=400, y=55, width=80, height=30)

FPL = tk.Label(root, text="File:", font=('Arial', 14))
FPL.place(x=40, y=135)

FPE = tk.Entry(root, state='readonly', width=60, font=('Arial', 12), textvariable=fpestr)
FPE.place(x=95, y=141)

DPL = tk.Label(root, text="Select Algorithm:", font=('Arial', 15))
DPL.place(x=40, y=197)

DPE = tk.OptionMenu(root, hashstr, *algorithms)
DPE.config(font=('Arial', 12))
DPE.place(x=200, y=195)

CHB = tk.Button(root, text="Check hash", font=('Arial', 12), command=hash().digest)
CHB.place(x=310, y=195)

HSL = tk.Label(root, text="Hash:", font=('Arial', 15))
HSL.place(x=40, y=300)

HSE = tk.Entry(root, state='readonly', font=('Arial', 12), textvariable=hashent, width=60)
HSE.place(x=100, y=305)

CHLm = tk.Label(root, text="Easily check the hash right or not.", font=('Arial', 9))
CHLm.place(x=40,y=365)

CHL = tk.Label(root, text="Check hash:", font=('Arial', 15))
CHL.place(x=40, y=395)

CHE = tk.Entry(root, state='disabled', font=('Arial', 12), width=60)
CHE.place(x=170, y=395)

CHB = tk.Button(root, state='disabled', text='Verify', font=('Arial', 13), command=hash().verify)
CHB.place(x=40, y=435)

root.mainloop()