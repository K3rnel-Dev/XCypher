import subprocess
from time import sleep
import sys
import termios
import tty
import base64
import codecs

Black = '\033[1;30m'        # Black
Red = '\033[1;31m'          # Red
Green = '\033[1;32m'        # Green
Yellow = '\033[1;33m'       # Yellow
Blue = '\033[1;34m'         # Blue
Purple = '\033[1;35m'       # Purple
Cyan = '\033[1;36m'         # Cyan
White = '\033[1;37m'        # White
NC = '\033[0m'
blue = '\033[0;34m'
white = '\033[0;37m'
lred = '\033[0;31m'


def logo():
    print(f'''{Blue}
     ▄▀▀▄  ▄▀▄  ▄▀▄▄▄▄   ▄▀▀▄ ▀▀▄  ▄▀▀▄ ▄▄   ▄▀▀▄▀▀▀▄  ▄▀▀█▄▄▄▄  ▄▀▀▄▀▀▀▄ 
    █    █   █ █ █    ▌ █   ▀▄ ▄▀ █  █   ▄▀ █   █   █ ▐  ▄▀   ▐ █   █   █ 
    ▐     ▀▄▀  ▐ █      ▐     █   ▐  █▄▄▄█  ▐  █▀▀▀▀    █▄▄▄▄▄  ▐  █▀▀█▀  
         ▄▀ █    █            █      █   █     █        █    ▌   ▄▀    █  
        █  ▄▀   ▄▀▄▄▄▄▀     ▄▀      ▄▀  ▄▀   ▄▀        ▄▀▄▄▄▄   █     █   
      ▄▀  ▄▀   █     ▐      █      █   █    █          █    ▐   ▐     ▐   
     █    ▐    ▐            ▐      ▐   ▐    ▐          ▐                  {Blue}

                          {Blue}-=Created by K3rnel-Dev-=
                    -=Github:https://github.com/K3rnel-dev-={Blue}
        ''')



def main():
    subprocess.call('clear')
    logo()
    print("\n")
    print(f"{Blue}+-------------------------------------------------------+")
    print(f"+\t{Green}          Available Cyphers    {Blue}                 +")
    print(f"{Blue}+-------------------------------------------------------+{NC}")
    print(f"{Blue}+ {White}[0] {Purple}Exit{Yellow}\t{Blue}\t\t\t\t\t+")
    print(f"{Blue}+ {White}[1] {Purple}Caesar Cipher{Yellow}\t{Blue}\t\t\t\t+")
    print(f"+ {White}[2] {Purple}Base85{Yellow}\t{Blue}\t\t\t\t\t+")
    print(f"+ {White}[3] {Purple}Base64{Yellow}\t{Blue}\t\t\t\t\t+")
    print(f"+ {White}[4] {Purple}Base58{Yellow}\t{Blue}\t\t\t\t\t+")
    print(f"+ {White}[5] {Purple}Base16{Yellow}\t{Blue}\t\t\t\t\t+")
    print(f"+ {White}[6] {Purple}Base32{Yellow}\t{Blue}\t\t\t\t\t+")
    print(f"+ {White}[7] {Purple}ROT13{Yellow}\t{Blue}\t\t\t\t\t+")
    print(f"+ {White}[8] {Purple}HEX{Yellow}\t{Blue}\t\t\t\t\t+")
    print(f"+ {White}[9] {Purple}Morse Code{Yellow}\t{Blue}\t\t\t\t+")
    print(f"+ {White}[x] {Purple}Binary{Yellow}\t{Blue}\t\t\t\t\t+")
    print(f"{Blue}+-------------------------------------------------------+")
    sleep(0.3)
    print(Blue + "[#] Select cypher: " + White, end='', flush=True)
    cypher_type = getch()
    while cypher_type not in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'x']:
        print(f"{Red}[-] You entered an invalid option!{NC}")
        print(Blue + "[#] Select cypher type: " + White, end='', flush=True)
        cypher_type = getch()

    if cypher_type == '0':
        # Выход
        sys.exit()

    subprocess.call('clear')
    logo()
    print("\n")
    print(f"{Blue}+-------------------------------------------------------+")
    print(f"+\t{Green}          Selected Cypher: {Purple}{cypher_type}    {Blue}       \t\t+")
    print(f"{Blue}+-------------------------------------------------------+{NC}")
    print(f"{Blue}+ {White}[1] {Purple}Encrypt{Yellow}\t{Blue}\t\t\t\t\t+")
    print(f"+ {White}[2] {Purple}Decrypt{Yellow}\t{Blue}\t\t\t\t\t+")
    print(f"+ {White}[b] {Purple}Back{Yellow}\t\t{Blue}\t\t\t\t+")
    print(f"{Blue}+-------------------------------------------------------+")
    sleep(0.3)
    print(Blue + "[#] Select operation: " + White, end='', flush=True)
    operation_type = getch()
    while operation_type not in ['1', '2', 'b']:
        print(f"{Red}[-] You entered an invalid option!{NC}")
        print(Blue + "[#] Select operation: " + White, end='', flush=True)
        operation_type = getch()

    if operation_type == '1':
        # Шифрование
        if cypher_type == '1':
            # Caesar Cipher
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to encrypt: {White}")
            shift = int(input(f"{Yellow}[#] Enter shift value: {White}"))
            encrypted_text = caesar_encrypt(text, shift)
            print(f"{Green}[+] Encrypted text: {White}{encrypted_text}")
        elif cypher_type == '2':
            # Base85
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to encrypt: {White}")
            encoded_text = base85_encode(text)
            print(f"{Green}[+] Encoded text: {White}{encoded_text}")
        elif cypher_type == '3':
            # Base64
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to encrypt: {White}")
            encoded_text = base64_encode(text)
            print(f"{Green}[+] Encoded text: {White}{encoded_text}")
        elif cypher_type == '4':
            # Base58
            subprocess.call('clear')
            logo()
            print('[-]Sorry this not work:(')
        elif cypher_type == '5':
            # Base45
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to encrypt: {White}")
            encoded_text = base45_encode(text)
            print(f"{Green}[+] Encoded text: {White}{encoded_text}")
        elif cypher_type == '6':
            # Base32
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to encrypt: {White}")
            encoded_text = base32_encode(text)
            print(f"{Green}[+] Encoded text: {White}{encoded_text}")
        elif cypher_type == '7':
            # ROT13
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to encrypt: {White}")
            encrypted_text = rot13_encrypt(text)
            print(f"{Green}[+] Encrypted text: {White}{encrypted_text}")
        elif cypher_type == '8':
            # HEX
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to encrypt: {White}")
            encoded_text = hex_encode(text)
            print(f"{Green}[+] Encoded text: {White}{encoded_text}")
        elif cypher_type == '9':
            # Morse Code
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to encrypt: {White}")
            encoded_text = morse_code_encode(text)
            print(f"{Green}[+] Encoded text: {White}{encoded_text}")
        elif cypher_type == 'x':
            # Binary
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to encrypt: {White}")
            encoded_text = binary_encode(text)
            print(f"{Green}[+] Encoded text: {White}{encoded_text}")

    elif operation_type == '2':
        # Дешифрование
        if cypher_type == '1':
            # Caesar Cipher
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to decrypt: {White}")
            shift = int(input(f"{Yellow}[#] Enter shift value: {White}"))
            decrypted_text = caesar_decrypt(text, shift)
            print(f"{Green}[+] Decrypted text: {White}{decrypted_text}")
        elif cypher_type == '2':
            # Base85
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to decrypt: {White}")
            decoded_text = base85_decode(text)
            print(f"{Green}[+] Decoded text: {White}{decoded_text}")
        elif cypher_type == '3':
            # Base64
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to decrypt: {White}")
            decoded_text = base64_decode(text)
            print(f"{Green}[+] Decoded text: {White}{decoded_text}")
        elif cypher_type == '4':
            subprocess.call('clear')
            logo()
            print('Sorry this not work!')
        elif cypher_type == '5':
            # Base45
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to decrypt: {White}")
            decoded_text = base45_decode(text)
            print(f"{Green}[+] Decoded text: {White}{decoded_text}")
        elif cypher_type == '6':
            # Base32
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to decrypt: {White}")
            decoded_text = base32_decode(text)
            print(f"{Green}[+] Decoded text: {White}{decoded_text}")
        elif cypher_type == '7':
            # ROT13
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to decrypt: {White}")
            decrypted_text = rot13_decrypt(text)
            print(f"{Green}[+] Decrypted text: {White}{decrypted_text}")
        elif cypher_type == '8':
            # HEX
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to decrypt: {White}")
            decoded_text = hex_decode(text)
            print(f"{Green}[+] Decoded text: {White}{decoded_text}")
        elif cypher_type == '9':
            # Morse Code
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to decrypt: {White}")
            decoded_text = morse_code_decode(text)
            print(f"{Green}[+] Decoded text{decoded_text}")
        elif cypher_type == '10':
            # Binary
            subprocess.call('clear')
            logo()
            text = input(f"{Yellow}[#] Enter text to decrypt: {White}")
            decoded_text = binary_decode(text)
            print(f"{Green}[+] Decoded text: {White}{decoded_text}")

    elif operation_type.lower() == 'b':
        # Возврат к выбору шифра
        main()

    print("\n")
    print(f"{Blue}+-------------------------------------------------------+")
    print(f"+ {Green}Operation completed!{NC}\t\t\t\t\t+")
    print(f"{Blue}+-------------------------------------------------------+")
    print(f"{Blue}+ {White}[b] {Purple}Back to Cyphers{Yellow}\t{Blue}\t\t\t\t+")
    print(f"{Blue}+ {White}[q] {Purple}Quit{Yellow}\t\t{Blue}\t\t\t\t+")
    print(f"{Blue}+-------------------------------------------------------+")
    sleep(0.3)
    print(Blue + "[#] Select option: " + White, end='', flush=True)
    option = getch()
    while option.lower() not in ['b', 'q']:
        print(f"{Red}[-] You entered an invalid option!{NC}")
        print(Blue + "[#] Select option: " + White, end='', flush=True)
        option = getch()

    if option.lower() == 'b':
        # Возврат к выбору операции
        main()
    elif option.lower() == 'q':
        # Выход из программы
        sys.exit()


# Шифрование методом Цезаря
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            encrypted_text += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            encrypted_text += char
    return encrypted_text


# Дешифрование методом Цезаря
def caesar_decrypt(text, shift):
    decrypted_text = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            decrypted_text += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
        else:
            decrypted_text += char
    return decrypted_text


# Кодирование в Base85
def base85_encode(text):
    encoded_bytes = base64.b85encode(text.encode())
    encoded_text = encoded_bytes.decode()
    return encoded_text


# Декодирование из Base85
def base85_decode(text):
    decoded_bytes = base64.b85decode(text.encode())
    decoded_text = decoded_bytes.decode()
    return decoded_text


# Кодирование в Base64
def base64_encode(text):
    encoded_bytes = base64.b64encode(text.encode())
    encoded_text = encoded_bytes.decode()
    return encoded_text


# Декодирование из Base64
def base64_decode(text):
    decoded_bytes = base64.b64decode(text.encode())
    decoded_text = decoded_bytes.decode()
    return decoded_text


# Кодирование в Base45
def base45_encode(text):
    encoded_bytes = base64.b16encode(text.encode())
    encoded_text = encoded_bytes.decode()
    return encoded_text


# Декодирование из Base45
def base45_decode(text):
    decoded_bytes = base64.b16decode(text.encode())
    decoded_text = decoded_bytes.decode()
    return decoded_text


# Кодирование в Base32
def base32_encode(text):
    encoded_bytes = base64.b32encode(text.encode())
    encoded_text = encoded_bytes.decode()
    return encoded_text

# Кодирование в base


# Декодирование из Base32
def base32_decode(text):
    decoded_bytes = base64.b32decode(text.encode())
    decoded_text = decoded_bytes.decode()
    return decoded_text


# Шифрование методом ROT13
def rot13_encrypt(text):
    encrypted_text = codecs.encode(text, 'rot_13')
    return encrypted_text


# Дешифрование методом ROT13
def rot13_decrypt(text):
    decrypted_text = codecs.encode(text, 'rot_13')
    return decrypted_text


# Кодирование в HEX
def hex_encode(text):
    encoded_text = text.encode().hex()
    return encoded_text


# Декодирование из HEX
def hex_decode(text):
    decoded_text = bytes.fromhex(text).decode()
    return decoded_text


# Кодирование в код Морзе
def morse_code_encode(text):
    morse_code_dict = {'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....',
                       'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.',
                       'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
                       'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
                       '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.', '.': '.-.-.-', ',': '--..--',
                       '?': '..--..', "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...',
                       ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.',
                       '$': '...-..-', '@': '.--.-.', ' ': '/', '\n': '\n'}
    encoded_text = ''
    for char in text:
        encoded_char = morse_code_dict.get(char.upper())
        if encoded_char:
            encoded_text += encoded_char + ' '
    return encoded_text


# Декодирование из кода Морзе
def morse_code_decode(text):
    morse_code_dict = {'.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
                       '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
                       '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
                       '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
                       '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9', '.-.-.-': '.', '--..--': ',',
                       '..--..': '?', '.----.': "'", '-.-.--': '!', '-..-.': '/', '-.--.': '(', '-.--.-': ')', '.-...': '&',
                       '---...': ':', '-.-.-.': ';', '-...-': '=', '.-.-.': '+', '-....-': '-', '..--.-': '_', '.-..-.': '"',
                       '...-..-': '$', '.--.-.': '@', '/': ' ', '\n': '\n'}
    decoded_text = ''
    encoded_chars = text.split(' ')
    for char in encoded_chars:
        decoded_char = morse_code_dict.get(char)
        if decoded_char:
            decoded_text += decoded_char
    return decoded_text


# Кодирование в двоичную систему
def binary_encode(text):
    encoded_text = ' '.join(format(ord(char), '08b') for char in text)
    return encoded_text


# Декодирование из двоичной системы
def binary_decode(text):
    binary_chars = text.split(' ')
    decoded_text = ''
    for char in binary_chars:
        decoded_char = chr(int(char, 2))
        decoded_text += decoded_char
    return decoded_text

def getch():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch


if __name__ == '__main__':
    main()