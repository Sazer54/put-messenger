import tkinter as tk
import socket
import threading
import sys
from tkinter import messagebox
import queue
import re

class RegistrationDialog(tk.Toplevel):
    def __init__(self, parent, sockfd):
        super().__init__(parent)
        self.sockfd = sockfd

        self.title("Register")
        self.geometry("400x300")
        self.configure(bg='#ffffe0')

        self.usernameLabel = tk.Label(self, text="Username:", font=("Arial", 14), bg='#ffffe0')
        self.usernameLabel.pack(padx=20, pady=10)

        self.usernameEntry = tk.Entry(self, font=("Arial", 12)) 
        self.usernameEntry.pack(padx=20, pady=10)


        self.passwordLabel = tk.Label(self, text="Password:", font=("Arial", 14), bg='#ffffe0')
        self.passwordLabel.pack(padx=20, pady=10)

        self.passwordEntry = tk.Entry(self, font=("Arial", 12), show="*") 
        self.passwordEntry.pack(padx=20, pady=10)

        self.registerButton = tk.Button(self, text="Register", command=self.handleRegister, font=("Arial", 12), bg='white')
        self.registerButton.pack(padx=20, pady=10)

        self.bind('<Return>', lambda event: self.handleRegister())

    def handleRegister(self):
        username = self.usernameEntry.get()
        password = self.passwordEntry.get()

        if not re.match("^[a-zA-Z0-9_]*$", username):
            messagebox.showerror("Registration Error", "Username should only contain letters, numbers, and underscores!")
            return

        register_message = f"REGISTER_{username}_{password}"
        self.sockfd.send(register_message.encode())
        messagebox.showinfo("Registration", "User registered successfully!")
        self.destroy()

class LoginDialog(tk.Toplevel):
    def __init__(self, parent, sockfd):
        super().__init__(parent)
        self.sockfd = sockfd
        self.login_successful = False
        self.queues = Queues()

        self.title("Login")
        self.geometry("400x300")  
        self.configure(bg='lightblue') 

        self.usernameLabel = tk.Label(self, text="Username:", font=("Arial", 14), bg='lightblue')
        self.usernameLabel.pack(padx=20, pady=10)

        self.usernameEntry = tk.Entry(self, font=("Arial", 12))
        self.usernameEntry.pack(padx=20, pady=10)

        self.passwordLabel = tk.Label(self, text="Password:", font=("Arial", 14), bg='lightblue')
        self.passwordLabel.pack(padx=20, pady=10)

        self.passwordEntry = tk.Entry(self, font=("Arial", 12), show="*")
        self.passwordEntry.pack(padx=20, pady=10)

        self.loginButton = tk.Button(self, text="Login", command=self.handleLogin, font=("Arial", 12), bg='white')
        self.loginButton.pack(padx=20, pady=10)

        self.registerButton = tk.Button(self, text="Register", command=self.openRegistrationDialog, font=("Arial", 12), bg='#ffffe0')
        self.registerButton.pack(padx=20, pady=10)

        self.bind('<Return>', lambda event: self.handleLogin())

        self.after(100, self.check_queue)

    def handleLogin(self):
        username = self.usernameEntry.get()
        password = self.passwordEntry.get()
        login_message = f"LOGIN_{username}_{password}"
        self.sockfd.send(login_message.encode())
    
    def openRegistrationDialog(self):
        RegistrationDialog(self, self.sockfd)

    def check_queue(self):
        try:
            message = self.queues.general.get_nowait()
            if message.startswith("LOGIN_FAIL"):
                messagebox.showerror("Login Failed", "Invalid username or password", parent=self)
            elif message.startswith("LOGIN_SUCCESS"):
                self.login_successful = True
                self.destroy()
                username = message.split('_')[2]
                FriendsDialog(self.master, self.sockfd, username)
        except queue.Empty:
            pass
        finally:
            self.after(100, self.check_queue)

    def destroy(self):
        if not self.login_successful:
            self.sockfd.send("EXIT".encode())
        super().destroy()

class AddFriendDialog(tk.Toplevel):
    def __init__(self, parent, sockfd, username, friends):
        super().__init__(parent)
        self.sockfd = sockfd
        self.queues = Queues()
        self.username = username
        self.friends = friends

        self.configure(bg='#E6FEB4') 

        self.title(f"{username}: Add Friend")
        self.geometry("300x200") 

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure([0, 1, 2], weight=1)

        self.label = tk.Label(self, text="Enter friend's username:", font=("Arial", 14), bg='#E6FEB4')
        self.label.grid(row=0, padx=20, pady=20)

        self.entry = tk.Entry(self, font=("Arial", 12))
        self.entry.grid(row=1, padx=20)

        self.addButton = tk.Button(self, text="Add", command=self.handleAdd, font=("Arial", 12), bg='white')
        self.addButton.grid(row=2, pady=20)

        self.bind('<Return>', lambda event: self.handleAdd())

    def handleAdd(self):
        friendUsername = self.entry.get()
        if friendUsername == self.username:
            messagebox.showerror("Error", "You cannot add yourself as a friend.", parent=self)
            return
        if friendUsername in self.friends:
            messagebox.showerror("Error", "This user is already your friend.", parent=self)
            return
        add_message = f"ADD_{self.username}_{friendUsername}"
        self.sockfd.send(add_message.encode())
        messagebox.showinfo("Added Friend", f"Added {friendUsername} as a friend successfully!", parent=self)
        self.destroy()

class FriendsDialog(tk.Toplevel):
    def __init__(self, parent, sockfd, username):
        super().__init__(parent)
        self.sockfd = sockfd
        self.username = username
        self.queues = Queues()

        self.geometry("300x500")

        header = tk.Frame(self, bg='#D6FE83')
        header.pack(fill=tk.X)

        welcomeLabel = tk.Label(header, text="Welcome, " + self.username, bg='#D6FE83', font=('Arial', 16, 'bold'))
        welcomeLabel.pack(padx=10, pady=10)

        friendsListHeader = tk.Frame(self, bg='#E6FEB4')
        friendsListHeader.pack(fill=tk.X)

        friendsListLabel = tk.Label(friendsListHeader, text="Friends list", font=('Arial', 14, 'bold'), bg='#E6FEB4')
        friendsListLabel.pack(padx=10, pady=10)

        self.title(f"{username}: Friends")

        self.friendsList = tk.Listbox(self, font=('Arial', 14, 'bold'))
        self.friendsList.pack(fill=tk.BOTH, expand=True)

        self.friendsList.bind('<Double-Button-1>', self.handleFriendClick)

        addFriendButtonFrame = tk.Frame(self, bg='#D6FE83')
        addFriendButtonFrame.pack(fill=tk.X, side=tk.BOTTOM)

        addFriendButton = tk.Button(addFriendButtonFrame, text="Add Friend", command=self.handleAddFriend, bg='white')
        addFriendButton.pack(side=tk.BOTTOM, padx=10, pady=10)

        self.refreshFriendsList()

        self.after(100, self.check_queue)
    
    def destroy(self):
        self.sockfd.sendall("EXIT".encode())
        super().destroy()

    def handleAddFriend(self):
        friends = list(self.friendsList.get(0, tk.END))
        AddFriendDialog(self, self.sockfd, self.username, friends)

    def refreshFriendsList(self):
        friends_message = f"FRIENDS_{self.username}"
        self.sockfd.send(friends_message.encode())
    
    def handleFriendClick(self, event):
        friendUsername = self.friendsList.get(self.friendsList.curselection())
        room_number_message = f"ROOMNUMBER_{self.username}_{friendUsername}"
        self.sockfd.send(room_number_message.encode())
        self.after(100, self.check_queue)

    def check_queue(self):
        try:
            message = self.queues.general.get_nowait()
            if not message.startswith("FRIENDS_") and not message.startswith("ROOMNUMBER_"):
                self.queues.general.put(message)
                return
            if message.startswith("ROOMNUMBER"):
                roomNumber, user1, user2 = message.split('_')[1:4]
                otherUser = user1 if self.username != user1 else user2
                RoomMessagesDialog(self, self.sockfd, self.username, roomNumber, otherUser)
            
            elif message.startswith("FRIENDS"):
                friends = message.split('_')[1].split(',')
                for friend in friends:
                    if friend:
                        self.friendsList.insert(tk.END, friend)
        except queue.Empty:
            pass
        finally:
            self.after(100, self.check_queue)

class CustomText(tk.Text):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(wrap='word')

class RoomMessagesDialog(tk.Toplevel):
    def __init__(self, parent, sockfd, username, roomNumber, otherUser):
        super().__init__(parent)
        self.sockfd = sockfd
        self.queues = Queues()
        self.username = username
        self.roomNumber = roomNumber
        self.otherUser = otherUser

        self.geometry("300x500")
        self.queues.rooms[self.roomNumber] = queue.Queue()

        header = tk.Frame(self, bg='#D6FE83')
        header.pack(fill=tk.X)

        chatHeaderLabel = tk.Label(header, text="Chat with: " + self.otherUser, bg='#D6FE83', font=('Arial', 14, 'bold'))
        chatHeaderLabel.pack(padx=10, pady=10)

        self.title(f"{username}: Chat with {otherUser}")

        self.messagesList = CustomText(self, font=('Arial', 14), state='disabled')
        self.messagesList.pack(fill=tk.BOTH, expand=True)

        self.scrollbar = tk.Scrollbar(self.messagesList)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.messagesList.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.messagesList.yview)

        messageFrame = tk.Frame(self, bg='#D6FE83')
        messageFrame.pack(fill=tk.X, side=tk.BOTTOM) 

        self.messageInput = tk.Entry(messageFrame, font=('Arial', 10))
        self.messageInput.pack(fill=tk.X)
        self.messageInput.bind('<Return>', self.handleSend)

        self.sendButton = tk.Button(messageFrame, text="Send", command=self.handleSend, bg='white')
        self.sendButton.pack(padx=10, pady=10)

        self.refreshMessagesList()
        self.after(100, self.check_queue)

    def destroy(self):
        leave_room_message = f"LEAVE_{self.roomNumber}_{self.username}"
        self.sockfd.send(leave_room_message.encode())
        super().destroy()

    def handleSend(self, event=None):
        text = self.messageInput.get()
        if text.strip():
            send_message = f"SEND_{self.username}_{self.roomNumber}_{text}"
            self.sockfd.send(send_message.encode())
        self.messageInput.delete(0, tk.END)

    def refreshMessagesList(self):
        enter_room_message = f"ENTER_{self.roomNumber}_{self.username}"
        self.sockfd.send(enter_room_message.encode())

        room_messages_message = f"ROOMMESSAGES_{self.roomNumber}"
        self.sockfd.send(room_messages_message.encode())

        self.after(100, self.check_queue)

    def check_queue(self):
        try:
            while True:
                message = self.queues.rooms[self.roomNumber].get_nowait()
                messages = message.split('\n')
                for message in messages:
                    if message:
                        prefix = f"MESSAGE_{self.roomNumber}_"
                        enter_prefix = f"ENTER_{self.roomNumber}_"
                        leave_prefix = f"LEAVE_{self.roomNumber}_"
                        if message.startswith(prefix):
                            message_text = message.split('_', 2)[2]
                            if message_text.strip():
                                self.messagesList.configure(state='normal') 

                                username, message = message_text.split(":", 1)

                                formatted_message = f"{username}: {message.strip()}\n"

                                self.messagesList.insert(tk.END, formatted_message)
                                self.messagesList.configure(state='disabled')
                                self.messagesList.yview(tk.END)
                        elif message.startswith(enter_prefix):
                            username = message.split('_', 2)[2]
                            enter_message = f"{username} has entered the chat.\n"
                            self.messagesList.configure(state='normal')
                            self.messagesList.tag_configure("bold", font=("Arial", 10, "bold"))
                            self.messagesList.insert(tk.END, enter_message, "bold")
                            self.messagesList.configure(state='disabled')
                            self.messagesList.yview(tk.END)
                        elif message.startswith(leave_prefix):
                            username = message.split('_', 2)[2]
                            leave_message = f"{username} has left the chat.\n"
                            self.messagesList.configure(state='normal')
                            self.messagesList.tag_configure("bold", font=("Arial", 10, "bold"))
                            self.messagesList.insert(tk.END, leave_message, "bold")
                            self.messagesList.configure(state='disabled')
                            self.messagesList.yview(tk.END)
        except queue.Empty:
            pass
        finally:
            self.after(100, self.check_queue)

class ReceiveThread(threading.Thread):
    def __init__(self, sockfd, app):
        super().__init__()
        self.sockfd = sockfd
        self.app = app
        self.queues = Queues()

    def run(self):
        while True:
            data = self.sockfd.recv(256)
            if not data:
                break
            message = data.decode()
            print("Server response:", message)

            if message == "EXIT":
                self.app.queue.put("EXIT")
                break

            if message.startswith('MESSAGE_') or message.startswith('ENTER_') or message.startswith('LEAVE_'):
                roomNumber = message.split('_', 3)[1]
                if roomNumber in self.queues.rooms:
                    self.queues.rooms[roomNumber].put(message)
            else:
                self.queues.general.put(message)

        self.sockfd.close()

class Queues:
    _shared_state = {
        'general': queue.Queue(),
        'rooms': {},
    }

    def __init__(self):
        self.__dict__ = self._shared_state

class MyApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.queue = queue.Queue()

        serv_addr = ('localhost', 12345)

        try:
            self.sockfd.connect(serv_addr)
        except Exception as e:
            print("Failed to connect:", e)
            sys.exit(1)

        self.withdraw()
        self.loginDialog = LoginDialog(self, self.sockfd)

        self.receiveThread = ReceiveThread(self.sockfd, self)
        self.receiveThread.start()

        self.after(100, self.check_queue)

    def check_queue(self):
        try:
            message = self.queue.get(0)
            if message == "EXIT":
                print("Exiting...")
                self.quit()
        except queue.Empty:
            pass
        self.after(100, self.check_queue)

if __name__ == "__main__":
    app = MyApp()
    app.mainloop()