import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES block size (128-bit)
BLOCK_SIZE = AES.block_size

# Generate a random AES key
key = os.urandom(BLOCK_SIZE)

# This function is usually on the server side
def oracle_encrypt(plaintext):
    """
    Encrypts the given plaintext using AES-128-CBC mode with PKCS#7 padding.
    
    Args:
        plaintext (bytes): The plaintext message to be encrypted.
    
    Returns:
        tuple: (IV, Ciphertext)
    """
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
    return cipher.iv, ciphertext

# This function is usually on the server side
def oracle_decrypt(iv, ciphertext):
    """
    Decrypts the given ciphertext using AES-128-CBC mode.
    
    Args:
        iv (bytes): Initialization vector.
        ciphertext (bytes): Encrypted data.
    
    Returns:
        bytes: The decrypted message (may still contain padding).
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)

# User or attacker side function
def check_padding(decrypt_func, iv, ciphertext):
    """
    Checks if the decrypted text has valid PKCS#7 padding.
    
    Args:
        decrypt_func (function): Decryption oracle function.
        iv (bytes): Initialization vector.
        ciphertext (bytes): Encrypted block.
    
    Returns:
        bool: True if padding is valid, False otherwise.
    """
    decrypted_text = decrypt_func(iv, ciphertext)
    try:
        unpad(decrypted_text, BLOCK_SIZE)
        return True
    except ValueError:
        return False

# User or attacker side function
def attack_block(ciphertext_block, check_padding_func, decrypt_func):
    """
    Performs a padding oracle attack on a single ciphertext block.
    
    Args:
        ciphertext_block (bytes): A single 16-byte AES block.
        check_padding_func (function): Function to check for valid padding.
        decrypt_func (function): Decryption oracle function.
    
    Returns:
        list: Decrypted block as a list of byte values.
    """
    decrypted_block = [0] * BLOCK_SIZE
    modified_iv = bytearray(BLOCK_SIZE)

    for padding_value in range(1, BLOCK_SIZE + 1):
        # Prepare the modified IV by applying the guessed padding
        for i in range(1, padding_value):
            modified_iv[-i] = decrypted_block[-i] ^ padding_value

        # Try all possible byte values (0-255) to find the correct padding
        for guess in range(256):
            modified_iv[-padding_value] = guess
            iv = bytes(modified_iv)

            if check_padding_func(decrypt_func, iv, ciphertext_block):
                # Extra check to avoid false positives when padding value is 1
                if padding_value == 1:
                    modified_iv[-2] ^= 1  # Flip an earlier byte to test
                    if not check_padding_func(decrypt_func, bytes(modified_iv), ciphertext_block):
                        continue  # False positive, continue guessing

                decrypted_block[-padding_value] = guess ^ padding_value
                break
        else:
            raise ValueError("No valid padding byte found. Ensure the oracle is functioning correctly.")

    return decrypted_block

# User or attacker side function
def attack_ciphertext(iv, ciphertext, check_padding_func, decrypt_func):
    """
    Performs a full padding oracle attack to decrypt an AES-CBC encrypted message.
    
    Args:
        iv (bytes): Initialization vector.
        ciphertext (bytes): Ciphertext to be decrypted.
        check_padding_func (function): Function to validate padding.
        decrypt_func (function): Decryption oracle function.
    
    Returns:
        bytes: Decrypted message without padding.
    """
    if len(iv) != BLOCK_SIZE or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Invalid IV or ciphertext length.")

    decrypted_message = bytearray()
    blocks = [iv] + [ciphertext[i:i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]

    for i in range(1, len(blocks)):  # Iterate over each ciphertext block
        decrypted_block = attack_block(blocks[i], check_padding_func, decrypt_func)
        plaintext_block = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(blocks[i - 1], decrypted_block))
        decrypted_message.extend(plaintext_block)

    return bytes(decrypted_message)

def main():
    """
    Main function to demonstrate a padding oracle attack on AES-CBC encryption.
    """
    # Encoding plaintext to base64 before encryption
    plaintext = base64.b64encode(b'This is the Padding Oracle Attack on 128 bit AES-CBC encryption!')

    # Encrypt the plaintext using AES-CBC
    iv, ciphertext = oracle_encrypt(plaintext)
    print("Ciphertext (hex value):", ciphertext.hex())
    print("Starting padding oracle attack...")

    # Execute the attack to recover plaintext
    recovered_plaintext = attack_ciphertext(iv, ciphertext, check_padding, oracle_decrypt)

    # Remove padding and decode the base64-encoded original message
    plaintext = unpad(recovered_plaintext, BLOCK_SIZE)
    print("Recovered plaintext:", base64.b64decode(plaintext).decode('ascii'))

if __name__ == "__main__":
    main()
