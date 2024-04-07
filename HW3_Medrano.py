# This is the template for Problem 1 only.
# For problems 2 and 3, keep the class definitions
# the same and rewrite the main program
import rsa
key_size = 2048

class Sender:
    def __init__(self, key_size):
        self.pubkey, self.privkey = rsa.newkeys(key_size)
        self.key_size = key_size
        self.plaintext_message = None
        self.key_pair = None
        self.public_key = None
        self.private_key = None
        self.hash_value = None
        self.signature = None
        self.ciphertext = None

    def encrypt(self, plaintext):
        self.plaintext_message = plaintext
        self.ciphertext = rsa.encrypt(plaintext, self.pubkey)
        return self.ciphertext
    
    def sign(self, plaintext):
        self.hash_value = rsa.compute_hash(plaintext, 'SHA-256')
        self.signature = rsa.sign(self.hash_value, self.privkey, 'SHA-256')
        return self.signature

class Receiver:
    def __init__(self, key_size):
        self.pubkey, self.privkey = rsa.newkeys(key_size)
        self.key_size = key_size

    def decrypt(self, ciphertext):
        return rsa.decrypt(ciphertext, self.privkey)
    
    def verify(self, plaintext, signature):
        return rsa.verify(plaintext, signature, self.pubkey)

if __name__ == "__main__":
    with open('message1.txt', 'rb') as file:
        plaintext = file.read()
    # initialize sender and receiver objects with 2048 key_size
    key_size = 2048
    sender = Sender(key_size)
    print(sender.encrypt(plaintext))
    sender.sign(plaintext)
    receiver = Receiver(key_size)
