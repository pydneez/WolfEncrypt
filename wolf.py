from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
import base64
import json

# =====================================================
# PLAYER CLASS
# =====================================================


class Player:
    def __init__(self, name):
        self.name = name

        # Generate RSA key pair
        self.key = RSA.generate(2048)
        self.private_key = self.key
        self.public_key = self.key.publickey()

    def export_public_key(self):
        return self.public_key.export_key()

    def decrypt_session_key(self, encrypted_key):
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        return cipher_rsa.decrypt(encrypted_key)

    def decrypt_role_message(self, encrypted_message, session_key, iv):
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher_aes.decrypt(encrypted_message), AES.block_size)
        return decrypted.decode()


def receive_role(player, host_public_key, package):

    encrypted_session_key = base64.b64decode(
        package["encrypted_session_key"]
    )

    iv = base64.b64decode(package["iv"])

    ciphertext = base64.b64decode(package["ciphertext"])

    session_key = player.decrypt_session_key(
        encrypted_session_key
    )

    decrypted_json = player.decrypt_role_message(
        ciphertext,
        session_key,
        iv
    )

    data = json.loads(decrypted_json)

    role = data["role"]

    signature = base64.b64decode(
        data["signature"]
    )

    try:
        host_key = RSA.import_key(host_public_key)

        message_hash = SHA256.new(role.encode())

        pkcs1_15.new(host_key).verify(
            message_hash,
            signature
        )

        verified = True

    except:
        verified = False

    print("==============================")
    print(f"Player: {player.name}")
    print(f"Role: {role}")
    print(f"Signature Verified: {verified}")
    print("==============================")
    
# =====================================================
# HOST CLASS
# =====================================================


class Host:
    def __init__(self, name="GameHost"):
        self.name = name

        # Generate RSA key pair for host
        self.key = RSA.generate(2048)
        self.private_key = self.key
        self.public_key = self.key.publickey()

    def sign_message(self, message):
        message_hash = SHA256.new(message.encode())
        signature = pkcs1_15.new(self.private_key).sign(message_hash)
        return signature

    def verify_signature(self, message, signature):
        try:
            message_hash = SHA256.new(message.encode())
            pkcs1_15.new(self.public_key).verify(message_hash, signature)
            return True
        except:
            return False

    def encrypt_role_for_player(self, role_message, player_public_key):
        # =================================================
        # STEP 1 — SIGN MESSAGE
        # =================================================

        signature = self.sign_message(role_message)

        package = {
            "role": role_message,
            "signature": base64.b64encode(signature).decode(),
        }

        package_json = json.dumps(package)

        # =================================================
        # STEP 2 — GENERATE AES SESSION KEY
        # =================================================

        session_key = get_random_bytes(16)  # 128-bit AES key

        # =================================================
        # STEP 3 — ENCRYPT MESSAGE USING AES
        # =================================================

        cipher_aes = AES.new(session_key, AES.MODE_CBC)
        ciphertext = cipher_aes.encrypt(pad(package_json.encode(), AES.block_size))

        iv = cipher_aes.iv

        # =================================================
        # STEP 4 — ENCRYPT SESSION KEY USING RSA
        # =================================================

        recipient_key = RSA.import_key(player_public_key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)

        encrypted_session_key = cipher_rsa.encrypt(session_key)
        # =================================================
        # RETURN SECURE PACKAGE
        # =================================================

        return {
            "encrypted_session_key": base64.b64encode(encrypted_session_key).decode(),
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        }

    # =====================================================


# =====================================================
# MAIN PROGRAM
# =====================================================

if __name__ == "__main__":

    # Create host
    host = Host()

    # Create players
    alice = Player("Alice")
    bob = Player("Bob")
    charlie = Player("Charlie")

    # Assign roles
    roles = {alice: "Werewolf", bob: "Villager", charlie: "Seer"}

    # Host encrypts roles
    encrypted_packages = {}

    for player, role in roles.items():

        package = host.encrypt_role_for_player(role, player.export_public_key())

        encrypted_packages[player] = package

    # Players receive and decrypt roles
    for player in encrypted_packages:

        receive_role(player, host.public_key.export_key(), encrypted_packages[player])
