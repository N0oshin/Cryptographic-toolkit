from flask import Flask, render_template, request, url_for, flash, redirect, session
from werkzeug.exceptions import abort

app = Flask(__name__)
app.config['SECRET_KEY']= 'your secret key'

def caesar_cipher_encrypt(plaintext, shift):
    """
    Encrypts plaintext using the Caesar cipher with a given shift.
    """
    ciphertext = ""
    shift=int(shift)
    shift=shift%26
    for char in plaintext:
        if char.isalpha():
            # Determine whether the character is uppercase or lowercase
            if char.isupper():
                base = ord('A')
            else:
                base = ord('a')
            # Shift the character forward by the specified amount, adjusting for case
            shifted_char = chr((ord(char) - base + shift) % 26 + base)
        else:
            # Preserve non-alphabetic characters
            shifted_char = char
        ciphertext += shifted_char
    return ciphertext



def caesar_cipher_decrypt(ciphertext, shift):
    """
    Decrypts ciphertext using the Caesar cipher with a given shift.
    """
    shift=int(shift)
    shift=shift%26
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            # Determine whether the character is uppercase or lowercase
            if char.isupper():
                base = ord('A')
            else:
                base = ord('a')
            # Shift the character back by the specified amount, adjusting for case
            shifted_char = chr((ord(char) - base - shift) % 26 + base)
        else:
            # Preserve non-alphabetic characters
            shifted_char = char
        plaintext += shifted_char
    return plaintext


def vigenere_cipher_encrypt(plaintext, key):
    """
    Encrypts plaintext using the Vigenère cipher with a given key.
    """
    ciphertext = ""
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            # Determine the shift amount for this character based on the current key character
            shift = ord(key[key_index % len(key)].upper()) - ord('A')
            # Determine whether the character is uppercase or lowercase
            if char.isupper():
                base = ord('A')
            else:
                base = ord('a')
            # Shift the character forward by the specified amount, adjusting for case
            shifted_char = chr((ord(char) - base + shift) % 26 + base)
            # Update the index into the key for the next character
            key_index += 1
        else:
            # Preserve non-alphabetic characters
            shifted_char = char
        ciphertext += shifted_char
    return ciphertext
    
def vigenere_cipher_decrypt(ciphertext, key):
    """
    Decrypts ciphertext using the Vigenère cipher with a given key.
    """
    plaintext = ""
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            # Determine the shift amount for this character based on the current key character
            shift = ord(key[key_index % len(key)].upper()) - ord('A')
            # Determine whether the character is uppercase or lowercase
            if char.isupper():
                base = ord('A')
            else:
                base = ord('a')
            # Shift the character back by the specified amount, adjusting for case
            shifted_char = chr((ord(char) - base - shift) % 26 + base)
            # Update the index into the key for the next character
            key_index += 1
        else:
            # Preserve non-alphabetic characters
            shifted_char = char
        plaintext += shifted_char
    return plaintext

def affine_cipher_encrypt(plaintext, a, b):
    """
    Encrypts plaintext using the Affine cipher with given coefficients a and b.
    """
    ciphertext = ""
    a=int(a)
    b=int(b)
    for char in plaintext:
        if char.isalpha():
            # Determine the numerical value of the character
            if char.isupper():
                base = ord('A')
            else:
                base = ord('a')
            char_value = ord(char) - base
            # Apply the affine transformation
            transformed_value = (a * char_value + b) % 26
            # Convert the transformed value back to a character and add it to the ciphertext
            ciphertext += chr(transformed_value + base)
        else:
            # Preserve non-alphabetic characters
            ciphertext += char
    return ciphertext


def affine_cipher_decrypt(ciphertext, a, b):
    """
    Decrypts ciphertext using the Affine cipher with given coefficients a and b.
    """
    plaintext = ""
    a=int(a)
    b=int(b)
    # Find the modular inverse of a modulo 26
    for i in range(26):
        if (a * i) % 26 == 1:
            a_inv = i
            break
    else:
        raise ValueError("a is not invertible")
    for char in ciphertext:
        if char.isalpha():
            # Determine the numerical value of the character
            if char.isupper():
                base = ord('A')
            else:
                base = ord('a')
            char_value = ord(char) - base
            # Apply the inverse affine transformation
            transformed_value = (a_inv * (char_value - b)) % 26
            # Convert the transformed value back to a character and add it to the plaintext
            plaintext += chr(transformed_value + base)
        else:
            # Preserve non-alphabetic characters
            plaintext += char
    return plaintext



@app.route('/')
def index():
 return render_template('index.html')


"""     ceasar cyphar     """

@app.route('/caesar',methods=('GET','POST'))
def caesar():
        return render_template('caesar.html')


@app.route('/caesar_encryption',methods=('GET','POST'))
def caesar_encryption():
        if request.method == 'POST':
            msg= request.form['msg']
            key= request.form['key']
            
            cipher=caesar_cipher_encrypt(msg,key)
            return render_template('caesar_encryption.html',cipher=cipher,plain=msg,key=key)
        return render_template('caesar_encryption.html',cipher="",plain="",key=0)


@app.route('/caesar_decryption',methods=('GET','POST'))
def caesar_decryption():
        if request.method == 'POST':
            msg= request.form['msg']
            key= request.form['key']
            
            plain=caesar_cipher_decrypt(msg,key)
            return render_template('caesar_decryption.html',cipher=msg,plain=plain,key=key)
        return render_template('caesar_decryption.html')
        
        
   
   
   
"""      vigenere cyphar    """     
        
        
@app.route('/vigenere',methods=('GET','POST'))
def vigenere():      
        return render_template('vigenere.html')


@app.route('/vigenere_cipher_encryption',methods=('GET','POST'))
def vigenere_cipher_encryption():
        if request.method == 'POST':
            msg= request.form['msg']
            key= request.form['key'] 
            cipher=vigenere_cipher_encrypt(msg,key)
            return render_template('vigenere_cipher_encryption.html',cipher=cipher,plain=msg,key=key)
        return render_template('vigenere_cipher_encryption.html',cipher="",plain="",key="")
        
        
@app.route('/vigenere_decryption',methods=('GET','POST'))
def vigenere_decryption():
        if request.method == 'POST':
            msg= request.form['msg']
            key= request.form['key']
            
            plain=vigenere_cipher_decrypt(msg,key)
            return render_template('vigenere_decryption.html',cipher=msg,plain=plain,key=key)
            
        return render_template('vigenere_decryption.html',cipher="",plain="",key="")        
        


"""      affine cyphar      """ 

@app.route('/affine',methods=('GET','POST'))
def affine():
        return render_template('affine.html')



@app.route('/affine_encryption',methods=('GET','POST'))
def affine_encryption():
        if request.method == 'POST':
            msg= request.form['msg']
            a= request.form['a']
            b= request.form['b']
            if int(a) % 2 == 0 or int(a) % 13 == 0:
                flash('The value of "a" must be coprime with 26.')
                return redirect(url_for('affine_encryption',cipher="",plain="",a="",b=""))
            cipher=affine_cipher_encrypt(msg, a, b)
            return render_template('affine_encryption.html',cipher=cipher,plain=msg,a=a,b=b)
        return render_template('affine_encryption.html',cipher="",plain="",a="",b="")



@app.route('/affine_decryption',methods=('GET','POST'))
def affine_decryption():
    if request.method == 'POST':
            msg= request.form['msg']
            a= request.form['a']
            b= request.form['b']
            if int(a) % 2 == 0 or int(a) % 13 == 0:
                flash('The value of "a" must be coprime with 26.')
                return redirect(url_for('affine_decryption', cipher="",plain="", a="", b=""))
            plain = affine_cipher_decrypt(msg, a, b)
            return render_template('affine_decryption.html', plain=plain, cipher=msg, a=a, b=b)
    return render_template('affine_decryption.html',cipher="",plain="",a="",b="")
    
    
    
    
    
    
    
