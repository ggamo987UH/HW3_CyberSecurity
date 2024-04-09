import rsa
class Sender:
    def __init__(self, message, key_size=2048):
        self.message = message
        self.public_key, self.private_key = rsa.newkeys(key_size)
        self.hash = rsa.compute_hash(self.message, 'SHA-256')
        self.signature = None
        self.cipher = None

    def encrypt(self):
        self.cipher = rsa.encrypt(self.message, self.public_key) 

    def sign(self):
        self.signature = rsa.sign_hash(self.hash, self.private_key, 'SHA-256')

class Receiver:
    def __init__(self):
        self.plaintext = None
        self.private_key, self.public_key = None, None
        self.signature = None
        self.ciphertext = None

    def decrypt(self, cipher, private_key, public_key):
        self.ciphertext = cipher
        self.private_key = private_key
        self.public_key = public_key
        self.message = rsa.decrypt(self.ciphertext, self.private_key).decode('utf-8')
        print("Decrypted message:", self.message)


    def verify(self, message, signature, sender_public_key):
        self.signature = signature
        print('Verification:', rsa.verify(message, self.signature, sender_public_key))

if __name__ == "__main__":
    with open('message1.txt', 'rb') as file:
        plaintext = file.read()

    sender = Sender(plaintext)
    sender.encrypt()
    sender.sign()

    plaintext[0] = plaintext[0] + 1


    receiver = Receiver()
    receiver.decrypt(plaintext, sender.private_key, sender.public_key)
    receiver.verify(sender.message, sender.signature, sender.public_key)

