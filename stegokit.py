from typing import Optional
from PIL import Image
import base64
import wave
import cv2
import os
from cryptokit import CryptoKit

class StegoKit:
    """
    Handles steganography operations: hiding and revealing messages in images, audio, and video files.
    """
    def __init__(self):
        self.crypto = CryptoKit()

    def steg_hide(self, image_path: str, message: str, output_path: str, password: Optional[str] = None) -> str:
        if password:
            encrypted = self.crypto.aes_encrypt_message(message, password)
            message = base64.b64encode(encrypted).decode()
        img = Image.open(image_path)
        encoded = img.copy()
        width, height = img.size
        message += chr(0)  # Null-terminate
        data = ''.join([format(ord(i), '08b') for i in message])
        data_len = len(data)
        idx = 0
        for y in range(height):
            for x in range(width):
                pixel = list(img.getpixel((x, y)))
                for n in range(3):
                    if idx < data_len:
                        pixel[n] = pixel[n] & ~1 | int(data[idx])
                        idx += 1
                encoded.putpixel((x, y), tuple(pixel))
                if idx >= data_len:
                    break
            if idx >= data_len:
                break
        encoded.save(output_path)
        return output_path

    def steg_reveal(self, image_path: str, password: Optional[str] = None, max_length: int = 4096) -> str:
        img = Image.open(image_path)
        width, height = img.size
        bits = []
        char_list = []
        for y in range(height):
            for x in range(width):
                pixel = img.getpixel((x, y))
                for n in range(3):
                    bits.append(str(pixel[n] & 1))
                    if len(bits) == 8:
                        char = chr(int(''.join(bits), 2))
                        if char == chr(0):
                            msg = ''.join(char_list)
                            if password:
                                try:
                                    decrypted = self.crypto.aes_decrypt_message(base64.b64decode(msg), password)
                                    return decrypted
                                except Exception:
                                    return '(Wrong password or corrupted data)'
                            return msg
                        char_list.append(char)
                        if len(char_list) >= max_length:
                            return ''.join(char_list) + '... (truncated)'
                        bits = []
        if char_list:
            return ''.join(char_list) + '... (no null terminator found)'
        return '(No hidden message found or image not suitable)'

    def audio_steg_hide(self, audio_path: str, message: str, output_path: str, password: Optional[str] = None) -> str:
        if password:
            encrypted = self.crypto.aes_encrypt_message(message, password)
            message = base64.b64encode(encrypted).decode()
        message += chr(0)
        data = ''.join([format(ord(i), '08b') for i in message])
        with wave.open(audio_path, 'rb') as audio:
            params = audio.getparams()
            frames = bytearray(list(audio.readframes(audio.getnframes())))
        if len(data) > len(frames):
            raise ValueError('Message too large to hide in audio file.')
        for i in range(len(data)):
            frames[i] = (frames[i] & ~1) | int(data[i])
        with wave.open(output_path, 'wb') as audio:
            audio.setparams(params)
            audio.writeframes(bytes(frames))
        return output_path

    def audio_steg_reveal(self, audio_path: str, password: Optional[str] = None, max_length: int = 4096) -> str:
        with wave.open(audio_path, 'rb') as audio:
            frames = bytearray(list(audio.readframes(audio.getnframes())))
        bits = []
        char_list = []
        for b in frames:
            bits.append(str(b & 1))
            if len(bits) == 8:
                char = chr(int(''.join(bits), 2))
                if char == chr(0):
                    msg = ''.join(char_list)
                    if password:
                        try:
                            decrypted = self.crypto.aes_decrypt_message(base64.b64decode(msg), password)
                            return decrypted
                        except Exception:
                            return '(Wrong password or corrupted data)'
                    return msg
                char_list.append(char)
                if len(char_list) >= max_length:
                    return ''.join(char_list) + '... (truncated)'
                bits = []
        if char_list:
            return ''.join(char_list) + '... (no null terminator found)'
        return '(No hidden message found or audio not suitable)'

    def video_steg_hide(self, video_path: str, message: str, output_path: str, password: Optional[str] = None) -> str:
        if password:
            encrypted = self.crypto.aes_encrypt_message(message, password)
            message = base64.b64encode(encrypted).decode()
        message += chr(0)
        message_bits = ''.join([format(ord(i), '08b') for i in message])
        cap = cv2.VideoCapture(video_path)
        fourcc = cv2.VideoWriter_fourcc(*'XVID')
        fps = cap.get(cv2.CAP_PROP_FPS)
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
        bit_idx = 0
        success, frame = cap.read()
        while success:
            for y in range(frame.shape[0]):
                for x in range(frame.shape[1]):
                    for c in range(3):
                        if bit_idx < len(message_bits):
                            frame[y, x, c] = (frame[y, x, c] & ~1) | int(message_bits[bit_idx])
                            bit_idx += 1
            out.write(frame)
            success, frame = cap.read()
        cap.release()
        out.release()
        if bit_idx < len(message_bits):
            raise ValueError('Message too large to hide in video file.')
        return output_path

    def video_steg_reveal(self, video_path: str, password: Optional[str] = None, max_length: int = 4096) -> str:
        cap = cv2.VideoCapture(video_path)
        bits = []
        char_list = []
        while True:
            success, frame = cap.read()
            if not success:
                break
            for y in range(frame.shape[0]):
                for x in range(frame.shape[1]):
                    for c in range(3):
                        bits.append(str(frame[y, x, c] & 1))
                        if len(bits) == 8:
                            char = chr(int(''.join(bits), 2))
                            if char == chr(0):
                                msg = ''.join(char_list)
                                cap.release()
                                if password:
                                    try:
                                        decrypted = self.crypto.aes_decrypt_message(base64.b64decode(msg), password)
                                        return decrypted
                                    except Exception:
                                        return '(Wrong password or corrupted data)'
                                return msg
                            char_list.append(char)
                            if len(char_list) >= max_length:
                                cap.release()
                                return ''.join(char_list) + '... (truncated)'
                            bits = []
        cap.release()
        if char_list:
            return ''.join(char_list) + '... (no null terminator found)'
        return '(No hidden message found or video not suitable)' 