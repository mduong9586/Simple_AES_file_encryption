import os
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256


def encrypt(key, filename):
    chunksize = 64 * 1024
    outputFile = "(enc)" + filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)
    
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    
    with open(filename, 'rb') as inf:
        with open(outputFile, 'wb') as outf:
            outf.write(filesize.encode('utf-8'))
            outf.write(IV)
            
            while True:
                chunk = inf.read(chunksize)
                
                if len(chunk) == 0:
                    break
                elif len(chunk)%16 != 0:
                    chunk += b' '*(16-(len(chunk)%16))
                    
                outf.write(encryptor.encrypt(chunk))
                
def decrypt(key, filename):
    chunksize = 64 * 1024
    outputFile = "(dec)" + filename[11:]
    
    with open(filename, 'rb') as inf:
        filesize = int(inf.read(16))
        IV = inf.read(16)
        
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        
        with open(outputFile, 'wb') as outf:
            while True:
                chunk = inf.read(chunksize)
                
                if len(chunk) == 0 :
                    break
                
                outf.write(decryptor.decrypt(chunk))
                
            outf.truncate(filesize)
            
def getKey(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

def main():
    choice = input("(E)encrypt or (D)decrypt ")
    
    if choice == 'E':
        filename = input("File to encrypt: ")
        password = input("Password: ")
        encrypt(getKey(password), filename)
        print("Done.")
        
    elif choice == 'D':
        filename = input("File to decrypt: ")
        password = input("Password: ")
        decrypt(getKey(password), filename)
        print("Done.")
        
    else:
        print("No option selected, closing...")
        
main()