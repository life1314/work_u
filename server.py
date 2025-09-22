import socket
import threading
from tkinter import *


class PlainServer:
    def __init__(self):
        self.conn = None

        # 初始化UI
        self.window = Tk()
        self.window.title("Plain Text Server")
        self.setup_ui()
        threading.Thread(target=self.start_server, daemon=True).start()
        self.window.mainloop()

    def setup_ui(self):
        """设置用户界面"""
        # 状态标签
        self.status_label = Label(self.window, text="Waiting...", fg="gray")
        self.status_label.pack(pady=5)

        # 聊天记录区域
        self.chat_log = Text(self.window, height=15, width=50, state=DISABLED)
        self.chat_log.pack(padx=10, pady=5)

        # 输入框和发送按钮
        self.entry = Entry(self.window, width=40)
        self.entry.pack(pady=5)
        self.send_btn = Button(self.window, text="Send", command=self.send_message, state=DISABLED)
        self.send_btn.pack()

    def start_server(self):
        """启动服务器"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('localhost', 12345))
        sock.listen(1)
        self.update_status("Listening on port 12345", "blue")

        while True:
            self.conn, addr = sock.accept()
            self.update_status(f"Connected to {addr}", "green")
            self.send_btn.config(state=NORMAL)  # 启用发送按钮
            threading.Thread(target=self.receive_messages, daemon=True).start()

    def send_message(self):
        """发送明文消息"""
        message = self.entry.get()
        if not message:
            return

        try:
            self.conn.send(message.encode('utf-8'))
            self.update_chat(f"You: {message}")
            self.entry.delete(0, END)
        except Exception as e:
            self.update_chat(f"[Error] Send failed: {str(e)}")

    def receive_messages(self):
        """接收明文消息"""
        while True:
            try:
                data = self.conn.recv(1024)
                if not data:
                    break
                message = data.decode('utf-8')
                self.update_chat(f"Client: {message}")
            except Exception as e:
                self.update_chat(f"[Error] Connection lost: {str(e)}")
                break

    def update_chat(self, message):
        """更新聊天记录"""
        self.chat_log.config(state=NORMAL)
        self.chat_log.insert(END, message + "\n")
        self.chat_log.config(state=DISABLED)
        self.chat_log.see(END)

    def update_status(self, text, color):
        """更新状态栏"""
        self.status_label.config(text=text, fg=color)


if __name__ == "__main__":
    PlainServer()