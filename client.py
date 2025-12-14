import sys
import socket
import requests
import threading
import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox

# ------------------------- Connect to Server via Ngrok -------------------------

# Get public TCP address from remote ngrok API
res = requests.get("https://tight-phoenix-correctly.ngrok-free.app")
HOST, PORT = res.json()["public_url"].replace("tcp://", "").split(":")
PORT = int(PORT)

# Create socket client and connect to server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# ------------------------- User Authentication -------------------------

# Prompt user for username
usr = simpledialog.askstring("Login", "Enter your username:")
name = str(usr).strip()

# Validate username input
if usr is not None:
    if name == "":
        messagebox.showerror("Error", "Username cannot be empty.")
        sys.exit()
    else:
        # Only allow alphanumeric + underscores/hyphens/dots
        if not name.replace("_", "").replace("-", "").replace(".", "").isalnum():
            messagebox.showerror("Error", "Username can only have alphanumeric characters.")
            sys.exit()
        # Prompt for password
        password = simpledialog.askstring("Login", "Enter your password:", show="*")
        if password is not None:
            if password == "":
                messagebox.showerror("Error", "Password cannot be empty.")
                sys.exit()
        else:
            sys.exit()
else:
    sys.exit()

# Send login credentials to server
client.send(f"/auth|{name}|{password}".encode())
response = client.recv(1024).decode()

# Check if login was successful
if not response.startswith("LOGIN_SUCCESS"):
    messagebox.showerror("Login Failed", response)
    client.close()
    sys.exit()

current_chat = None  # Currently active chat room

# ------------------------- GUI Setup -------------------------

# Create main application window
window = tk.Tk()
window.title("PyChat")

# ---------- Left Panel: Chat List ----------
chat_frame_left = tk.Frame(window)
chat_frame_left.pack(side=tk.LEFT, fill=tk.Y)
chat_frame_left.config(bg='#010409')

chat_label = tk.Label(chat_frame_left, text="Chats", font=('TkDefaultFont', 13))
chat_label.pack()
chat_label.config(fg='white', bg='#010409')

chat_listbox = tk.Listbox(chat_frame_left, highlightthickness=1, font=('TkDefaultFont', 13), selectbackground='#2d3139')
chat_listbox.pack(padx=(10, 0), pady=(0, 10), fill=tk.BOTH, expand=True)
chat_listbox.config(fg='white', bg='#0d1117', highlightbackground ='#2d3139', borderwidth=0)

# ---------- Right Panel: Chat Display & Entry ----------
chat_frame_right = tk.Frame(window)
chat_frame_right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
chat_frame_right.config(bg='#010409')

# Message display area
messages = scrolledtext.ScrolledText(chat_frame_right, highlightthickness=1, font=('TkDefaultFont', 13))
messages.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
messages.config(state='disabled', fg='white', bg='#0d1117', highlightbackground ='#2d3139', borderwidth=0)

# Message input field
msg_entry = tk.Entry(chat_frame_right, highlightthickness=1, font=('TkDefaultFont', 13), insertbackground='white')
msg_entry.pack(padx=10, pady=(0, 10), fill=tk.X)
msg_entry.config(fg='white', bg='#0d1117', highlightbackground ='#2d3139', borderwidth=0)

# Placeholder label inside message entry
placeholder = tk.Label(msg_entry, text="Type here...", foreground='#646464', background='#0d1117', font=('TkDefaultFont', 13), anchor='w')
placeholder.place(x=2, y=0, relheight=1)

# Set minimum window size
window.update()
window.minsize(int(window.winfo_width()/2), window.winfo_height())

isempty = True  # Tracks if input field is empty

# ------------------------- Input Field Placeholder Logic -------------------------

def placeholding(event=None):
    global isempty
    if (not isempty and event.keysym == "BackSpace" and len(msg_entry.get()) == 1) or (event.keysym == "Return" and not coolingdown):
        placeholder.place(x=2, y=0, relheight=1)
        isempty = True
    elif isempty and len(msg_entry.get()) == 0 and event.char and event.keysym not in ["BackSpace", "Return", "Tab"]:
        placeholder.place_forget()
        isempty = False

def focus_it(event=None):
    msg_entry.focus()

# Bind focus and typing events to placeholder
placeholder.bind('<Button-1>', focus_it)
msg_entry.bind('<Key>', placeholding)

# ------------------------- Sending Messages -------------------------

coolingdown = False
COOLDOWN_TIME = 500  # ms

def reset_cooldown():
    global coolingdown
    coolingdown = False

def send_msg(event=None):
    global coolingdown, current_chat

    # Prevent Enter from inserting a new line / double firing
    if coolingdown:
        return

    msg = msg_entry.get().strip()
    if not msg or not current_chat:
        return

    coolingdown = True

    full_msg = f"{name}|{current_chat}|{msg}"
    client.send(full_msg.encode())
    msg_entry.delete(0, tk.END)

    window.after(COOLDOWN_TIME, reset_cooldown)

    return # Stops default Enter behavior

        

# ------------------------- Receiving Messages -------------------------

def receive():
    while True:
        try:
            data = client.recv(1024).decode()
            if not data:
                window.destroy()
                messagebox.showinfo("Info", "Disconnected from server. Please try again later.")
                sys.exit()
            lines = data.splitlines()
            messages.config(state='normal')
            for line in lines:
                # Highlight messages from self differently
                if line.startswith(name + ": "):
                    display = line.replace(name + ": ", "", 1)
                    messages.insert(tk.END, display + "\n", 'you')
                    messages.tag_config('you', foreground="#d2a8ff", justify="right")
                else:
                    display = line.partition(": ")
                    messages.insert(tk.END, display[0], 'tag')
                    messages.tag_config('tag', foreground="#ffa557")
                    messages.insert(tk.END, display[1], 'colon')
                    messages.tag_config('colon', foreground="#ff7b72")
                    messages.insert(tk.END, display[2] + '\n')
            messages.config(state='disabled')
            messages.yview(tk.END)
        except:
            break

# ------------------------- Chat Selection -------------------------

def join_selected_chat(event=None):
    global current_chat
    selection = chat_listbox.curselection()
    if not selection:
        return
    selected = chat_listbox.get(selection[0])
    # Clear chat display and show welcome message
    messages.config(state='normal')
    messages.delete('1.0', tk.END)
    messages.insert(tk.END, f"Welcome to {selected}\n", 'welcome')
    messages.tag_config('welcome', foreground='#ff7b72', justify='center')
    messages.config(state='disabled')
    # Inform server of new chat join
    join_msg = f"/join|{name}|{selected}|{current_chat or ''}"
    client.send(join_msg.encode())
    window.title(f"PyChat: {selected}")
    current_chat = selected

# ------------------------- Initialize GUI -------------------------

# Add default chat rooms
default_chats = ["General", "Gaming", "Study", "Music", "Projects"]
for chat in default_chats:
    chat_listbox.insert(tk.END, chat)

# Bind events
chat_listbox.bind("<<ListboxSelect>>", join_selected_chat)
chat_listbox.bind("<ButtonRelease-1>", focus_it)
window.bind("<Return>", send_msg)

# Select first chat by default
chat_listbox.selection_set(0)
join_selected_chat()
focus_it()

# ------------------------- Start Receive Thread and GUI Loop -------------------------

threading.Thread(target=receive, daemon=True).start()  # Start background receiver
window.mainloop()  # Start the GUI event loop
