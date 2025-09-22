import socket
import threading
import time
from tkinter import *
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from os import urandom
from cryptography.hazmat.primitives.asymmetric import dh


class RSA_DH_AES_Client:
    def __init__(self):
        self.conn = None
        self.hmac_key = None
        self.aes_key = None
        self.iv = None
        self.client_private_key = None
        self.server_public_key = None
        self.performance_data = {
            "key_exchange_time": 0.0,
            "send_count": 0,
            "recv_count": 0,
            "total_latency": 0.0,
            "crypto_time": 0.0
        }

        # 初始化UI
        self.window = Tk()
        self.window.title("RSA+DH+AES Client")
        self.setup_ui()
        threading.Thread(target=self.connect_to_server, daemon=True).start()
        self.window.mainloop()

    def setup_ui(self):
        """设置用户界面"""
        # 状态栏
        self.status_frame = Frame(self.window)
        self.status_frame.pack(pady=5)
        self.status_label = Label(self.status_frame, text="Waiting...", fg="gray")
        self.status_label.pack(side=LEFT, padx=10)
        self.performance_label = Label(self.status_frame,
                                       text="KeyEx: 0ms | Msgs: 0/0 | Latency: 0ms | HMAC/AES: 0ms")
        self.performance_label.pack(side=LEFT)

        # 聊天区域
        self.chat_log = Text(self.window, height=15, width=60, state=DISABLED)
        self.chat_log.pack(padx=10, pady=5)

        # 输入框和发送按钮
        self.input_frame = Frame(self.window)
        self.input_frame.pack(pady=5)
        self.entry = Entry(self.input_frame, width=50)
        self.entry.pack(side=LEFT)
        self.send_btn = Button(self.input_frame, text="Send", command=self.send_message, state=DISABLED)
        self.send_btn.pack(side=LEFT, padx=5)

    def connect_to_server(self):
        """连接到服务器并处理RSA密钥交换"""
        time.sleep(5)  # 等待服务器启动
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        start_time = time.time()  # Initialize start_time here

        try:
            self.conn.connect(('localhost', 12345))
            self.update_status("Connected", "green")

            # 1. 接收服务器公钥
            server_public_pem = self.conn.recv(4096)
            self.server_public_key = serialization.load_pem_public_key(server_public_pem)

            # 2. 生成RSA密钥对并发送公钥
            self.client_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            client_public_key = self.client_private_key.public_key()
            pem = client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.conn.send(pem)

            # 3. 接收DH参数
            dh_params_pem = self.conn.recv(4096)
            dh_params = serialization.load_pem_parameters(dh_params_pem)

            # 4. 生成DH私钥并发送公钥
            client_private_key_dh = dh_params.generate_private_key()
            client_public_key_dh = client_private_key_dh.public_key()
            self.conn.send(client_public_key_dh.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

            # 5. 接收服务器公钥
            server_public_pem_dh = self.conn.recv(4096)
            server_public_key_dh = serialization.load_pem_public_key(server_public_pem_dh)

            # 6. 生成共享密钥并派生HMAC密钥和AES密钥
            shared_key = client_private_key_dh.exchange(server_public_key_dh)
            kdf_hmac = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'hmac_key',
            )
            self.hmac_key = kdf_hmac.derive(shared_key)

            kdf_aes = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'aes_key',
            )
            self.aes_key = kdf_aes.derive(shared_key)

            # 7. 接收加密后的密钥和IV
            combined_encrypted_keys = self.conn.recv(4096)
            hmac_len = int.from_bytes(combined_encrypted_keys[:2], byteorder='big')
            aes_len = int.from_bytes(combined_encrypted_keys[2+hmac_len:4+hmac_len], byteorder='big')
            iv_len = int.from_bytes(combined_encrypted_keys[4+hmac_len+aes_len:6+hmac_len+aes_len], byteorder='big')

            encrypted_hmac_key = combined_encrypted_keys[2:2+hmac_len]
            encrypted_aes_key = combined_encrypted_keys[4+hmac_len:4+hmac_len+aes_len]
            encrypted_iv = combined_encrypted_keys[6+hmac_len+aes_len:6+hmac_len+aes_len+iv_len]

            # 8. 解密HMAC密钥、AES密钥和IV
            self.hmac_key = self.decrypt_with_rsa(encrypted_hmac_key, self.client_private_key)
            self.aes_key = self.decrypt_with_rsa(encrypted_aes_key, self.client_private_key)
            self.iv = self.decrypt_with_rsa(encrypted_iv, self.client_private_key)

            # 记录密钥交换时间
            key_ex_time = (time.time() - start_time) * 1000
            self.performance_data["key_exchange_time"] = key_ex_time
            self.update_performance()

            self.send_btn.config(state=NORMAL)
            self.update_chat("[System] RSA+DH密钥交换完成，HMAC和AES密钥已生成")
            threading.Thread(target=self.receive_messages, daemon=True).start()

        except Exception as e:
            self.update_chat(f"[Error] Key exchange failed: {str(e)}")
            if self.conn:
                self.conn.close()

    def decrypt_with_rsa(self, data, private_key):
        """使用RSA私钥解密数据"""
        return private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def send_message(self):
        """发送HMAC认证和AES加密的消息"""
        message = self.entry.get()
        if not message or not self.hmac_key or not self.aes_key or not self.iv:
            return

        try:
            # 添加时间戳计算延迟
            full_msg = f"{message}@{time.time()}"

            # 加密消息
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(self.iv))
            encryptor = cipher.encryptor()
            padded_msg = self.pad(full_msg.encode('utf-8'))
            encrypted_msg = encryptor.update(padded_msg) + encryptor.finalize()

            # 计算HMAC
            start_time = time.time()
            h = hmac.HMAC(self.hmac_key, hashes.SHA256())
            h.update(encrypted_msg)
            signature = h.finalize()
            crypto_time = (time.time() - start_time) * 1000

            # 发送消息
            payload = encrypted_msg + b'|' + signature.hex().encode('utf-8')
            self.conn.send(payload)

            # 更新性能数据
            self.performance_data["send_count"] += 1
            self.performance_data["crypto_time"] += crypto_time
            self.update_performance()

            self.update_chat(f"You: {message}")
            self.entry.delete(0, END)
        except Exception as e:
            self.update_chat(f"[Error] Send failed: {str(e)}")

    def receive_messages(self):
        """接收并验证和解密消息"""
        while True:
            try:
                data = self.conn.recv(1024)
                if not data:
                    break

                recv_time = time.time()
                encrypted_msg, signature_hex = data[:-65], data[-64:]  # Adjusted for hex signature
                signature = bytes.fromhex(signature_hex.decode('utf-8'))

                # 验证HMAC
                start_time = time.time()
                h = hmac.HMAC(self.hmac_key, hashes.SHA256())
                h.update(encrypted_msg)
                try:
                    h.verify(signature)
                    crypto_time = (time.time() - start_time) * 1000

                    # 解密消息
                    cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(self.iv))
                    decryptor = cipher.decryptor()
                    decrypted_padded_msg = decryptor.update(encrypted_msg) + decryptor.finalize()
                    decrypted_msg = self.unpad(decrypted_padded_msg).decode('utf-8')

                    # 计算延迟
                    if '@' in decrypted_msg:
                        message, timestamp = decrypted_msg.split('@')
                        latency = (recv_time - float(timestamp)) * 1000
                        self.performance_data["total_latency"] += latency
                    else:
                        message = decrypted_msg

                    # 更新性能数据
                    self.performance_data["recv_count"] += 1
                    self.performance_data["crypto_time"] += crypto_time
                    self.update_performance()

                    self.update_chat(f"Server: {message}")
                except Exception:
                    self.update_chat(f"[Security] 消息签名无效!")
            except Exception as e:
                self.update_chat(f"[Error] Receive failed: {str(e)}")
                break

    def update_performance(self):
        """更新性能显示"""
        avg_latency = self.performance_data["total_latency"] / self.performance_data["recv_count"] if \
        self.performance_data["recv_count"] > 0 else 0
        avg_crypto = (self.performance_data["crypto_time"] /
                      (self.performance_data["send_count"] + self.performance_data["recv_count"])) if (
                                                                                                                  self.performance_data[
                                                                                                                      "send_count"] +
                                                                                                                  self.performance_data[
                                                                                                                      "recv_count"]) > 0 else 0

        text = f"KeyEx: {self.performance_data['key_exchange_time']:.2f}ms | "
        text += f"Msgs: {self.performance_data['send_count']}/{self.performance_data['recv_count']} | "
        text += f"Latency: {avg_latency:.2f}ms | HMAC/AES: {avg_crypto:.2f}ms"
        self.performance_label.config(text=text)

    def update_chat(self, message):
        self.chat_log.config(state=NORMAL)
        self.chat_log.insert(END, message + "\n")
        self.chat_log.config(state=DISABLED)
        self.chat_log.see(END)

    def update_status(self, text, color):
        self.status_label.config(text=text, fg=color)

    def pad(self, data):
        padding_length = 16 - len(data) % 16
        padding = chr(padding_length) * padding_length
        return data + padding.encode('utf-8')

    def unpad(self, data):
        padding_length = data[-1]
        return data[:-padding_length]


if __name__ == "__main__":
    RSA_DH_AES_Client()



