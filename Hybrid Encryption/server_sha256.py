import socket
import os
import threading
from tkinter import *
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class SecureServer:
    def __init__(self):
        # 初始化DH参数
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
        self.dh_private_key = self.dh_parameters.generate_private_key()
        self.shared_key = None
        self.conn = None

        # 初始化UI
        self.window = Tk()
        self.window.title("Secure Server")
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
        """启动服务器并处理连接"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('localhost', 12345))
        sock.listen(1)
        self.update_status("Listening on port 12345", "blue")

        while True:
            self.conn, addr = sock.accept()
            self.update_status(f"Connected to {addr}", "green")

            try:
                # 1. 发送DH参数给客户端
                params_pem = self.dh_parameters.parameter_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.ParameterFormat.PKCS3
                )
                self.conn.send(params_pem)

                # 2. 接收客户端公钥并发送服务器公钥
                client_dh_pub = self.conn.recv(4096)
                client_dh_key = serialization.load_pem_public_key(client_dh_pub)

                server_dh_pub = self.dh_private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                self.conn.send(server_dh_pub)

                # 3. 生成共享密钥
                self.shared_key = self.dh_private_key.exchange(client_dh_key)
                self.update_chat("[System] DH Key Exchange Completed")
                self.send_btn.config(state=NORMAL)  # 启用发送按钮

                # 启动消息接收线程
                threading.Thread(target=self.receive_messages, daemon=True).start()

            except Exception as e:
                self.update_chat(f"[Error] Key exchange failed: {str(e)}")

    def send_message(self):
        """使用共享密钥加密并发送消息"""
        if not self.shared_key:
            self.update_chat("[Error] Key exchange not completed")
            return

        message = self.entry.get()
        if not message:
            return

        try:
            # 派生AES密钥
            kdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'aes_key',
            )
            aes_key = kdf.derive(self.shared_key)
            iv = os.urandom(16)

            # 加密消息
            ciphertext = self.encrypt_message(message.encode(), aes_key, iv)
            self.conn.send(iv + ciphertext)
            self.update_chat(f"You: {message}")
            self.entry.delete(0, END)

        except Exception as e:
            self.update_chat(f"[Error] Send failed: {str(e)}")

    def encrypt_message(self, data, key, iv):
        """AES-CBC加密"""
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return encryptor.update(padded) + encryptor.finalize()

    def receive_messages(self):
        """接收并解密消息"""
        while True:
            try:
                data = self.conn.recv(1024)
                if not data:
                    break

                iv = data[:16]
                ciphertext = data[16:]

                # 派生AES密钥
                kdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'aes_key',
                )
                aes_key = kdf.derive(self.shared_key)

                # 解密消息
                decrypted = self.decrypt_message(ciphertext, aes_key, iv)
                self.update_chat(f"Client: {decrypted.decode()}")

            except Exception as e:
                self.update_chat(f"[Error] Receive failed: {str(e)}")
                break

    def decrypt_message(self, ciphertext, key, iv):
        """AES-CBC解密"""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted_padded) + unpadder.finalize()

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
    SecureServer()