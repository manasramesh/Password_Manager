import sqlite3
import hashlib
import getpass
import base64
import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


db_name='data.db'
conn=sqlite3.connect(db_name)
curser=conn.cursor()
create_user_table = ''' CREATE TABLE IF NOT EXISTS user_table ( id INTEGER PRIMARY KEY, uname TEXT NOT NULL, password_hash TEXT NOT NULL ) '''
curser.execute(create_user_table)

def derive_key_from_password(password, salt, iterations=100000, key_length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key


def sha256_hash(value):
    # Encode the value as bytes (SHA-256 requires bytes input)
    value_bytes = value.encode('utf-8')
    
    # Create the SHA-256 hash object
    sha256_obj = hashlib.sha256()
    
    # Update the hash object with the encoded value
    sha256_obj.update(value_bytes)
    
    # Get the hexadecimal representation of the hash
    hash_value = sha256_obj.hexdigest()
    
    return hash_value
def authorised_activities(uname_id):
    print(" 1 : List all entries \n 2 : Search In entries  \n 3 : Add a new entry \n 4 : Del an entry")
    x=int(input("Enter your input : "))
    if x == 1:
        select_query = f'''SELECT * FROM {uname_id}'''
        curser.execute(select_query)
        rows = curser.fetchall()
        for row in rows:
            print(row)
    elif x==2:
        platform=input('Enter platform name : ')
        search_query = f'''SELECT * FROM {uname_id} WHERE platform = ? '''
        curser.execute(search_query, (platform))
        rows = curser.fetchall()
        for row in rows:
            print(row)


    elif x==3:
        platform, username, password=input("Enter Platform : "),input("Enter Username : "), input("Enter Password : ")
        insert_query = f'''INSERT INTO {uname_id} (platform, username, password) VALUES (?, ?, ?)'''
        curser.execute(insert_query, (platform, username, password))
        conn.commit()
    elif x==4:
        print()


def signin():
    uname_id=input("Enter your uname id : ")
    password = getpass.getpass("Enter password: ")
    hashed_value = sha256_hash(password)
    salt=b'hbdshbadshbywywe'
    symmetric_key = derive_key_from_password(password, salt)
    #print ( uname_id,hashed_value,symmetric_key.hex())
    check_name_query = '''
        SELECT COUNT(*) FROM user_table WHERE uname = ?
    '''
    curser.execute(check_name_query, (uname_id,))
    name_exists = curser.fetchone()[0] > 0
    if not name_exists:
        print("User Does Not Exist, Please sign up.")
        sys.exit()
    check_password_query = '''
        SELECT password_hash FROM user_table WHERE uname = ?
    '''
    curser.execute(check_password_query, (uname_id,))
    stored_password = curser.fetchone()
    stored_password_string= str(stored_password[0])
    print(type(stored_password_string), type(hashed_value))
    if stored_password_string.strip() == hashed_value.strip():
        print("Authentication successful. Password matches.")
        authorised_activities(uname_id)
    else:
        print("Authentication failed. Password does not match.")
        sys.exit()







def signup():
    uname_id=input("Enter your uname id : ")
    password = getpass.getpass("Enter password: ")
    hashed_value = sha256_hash(password)
    check_query = ''' SELECT COUNT(*) FROM user_table WHERE uname = ? '''
    curser.execute(check_query, (uname_id,))
    name_exists = curser.fetchone()[0] > 0
    if not name_exists:
        insert_query = '''
            INSERT INTO user_table (uname, password_hash) VALUES (?, ?)
        '''
        curser.execute(insert_query, (uname_id, hashed_value))

        conn.commit()
        create_table_query = f''' CREATE TABLE IF NOT EXISTS {uname_id} ( id INTEGER PRIMARY KEY, platform TEXT NOT NULL, username TEXT NOT NULL, password TEXT NOT NULL ) '''
        curser.execute(create_table_query)
        
        print("User Registered Successfully")
    else:
        print("Already registered user, Please login")
    

def main_menu():
    print("1 : Login  ||  2 : SignUp  ||  Any other key to Exit")
    x=input('Enter your choice : ')
    if x=='1':
        signin()
    elif x=='2':
        signup()
    else:
        print('Exited')


main_menu()
curser.close()
conn.close()

