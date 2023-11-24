def to_hex(input_string):
    byte_array = bytearray(input_string, 'utf-8')
    hex_string = ''.join('{:02x}'.format(byte) for byte in byte_array)

    return hex_string

def shellcode_format(bad_shellcode):
    print("[+] Cleaning the shellcode...")
    cleaned_shellcode = bad_shellcode.replace("\\x", "")
    print("[+] Shellcode cleaned successfully!")

    return cleaned_shellcode

def rc4_encrypt(key, data):
    S = list(range(256))
    j = 0
    out = []

    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append('{:02x}'.format(char ^ S[(S[i] + S[j]) % 256]))

    return ''.join(out)
    
def shell_final_format(shellcode):
    final = ""
    for i in range(0, len(shellcode), 2):
        final += "\\x" + shellcode[i:i+2]
    return final

def menu():
    print("1) String RC4 encryption")
    print("2) Shellcode RC4 encryption")
    print("q) Quit")
    choice = input("-->")
    return choice

def main():
    stop = False
    while not stop:
        choice = menu()

        if choice == "q":
            print("Bye!")
            break

        elif choice == "1":
            user_string = input("Enter a string: ")
            user_key = input("Enter a key: ")
            hex_user_string = to_hex(user_string)
            hex_user_key = to_hex(user_key)
            print("\n[+] Hex representation of the key:", hex_user_key)
            encrypted_string = rc4_encrypt(user_key.encode('utf-8'), user_string.encode('utf-8'))
            print("[+] Encrypted string:", encrypted_string, "\n")

        elif choice == "2":
            user_shellcode = input("Input a shellcode of your choice: ")
            user_key = input("Enter a key: ")
            hex_user_key = to_hex(user_key)
            print("\n[+] Hex representation of the key:", hex_user_key)
            cleaned_shellcode = shellcode_format(user_shellcode)
            encrypted_shellcode = rc4_encrypt(user_key.encode('utf-8'), bytes.fromhex(cleaned_shellcode))
            print("[+] Encrypted shellcode:", encrypted_shellcode)
            final = shell_final_format(encrypted_shellcode)
            print("[+] Cool looking encrypted shellcode: ", final, "\n")
            
        else:
            input("Wrong choice...")

if __name__ == "__main__":
    main()
