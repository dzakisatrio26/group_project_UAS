#store login data 

#Function for login and store login data includes security
from os import system
import hashlib
import sqlite3
import os
import msvcrt
from tabulate import tabulate
from datetime import datetime
import time
import json

##################### BAGIAN FUNGSI UNTUK KEPENTINGAN LOG IN DAN PEMBUATAN AKUN USER #####################

# Inisialisasi direktori baru untuk db
try:
    os.mkdir("./saves")
except FileExistsError:
    pass

# Menggunakan path yang sesuai untuk database
db_path = 'saves/db.sqlite'

# Membuat koneksi ke database
con = sqlite3.connect(db_path)
cur = con.cursor()

# Membuat tabel "auth" jika belum ada
try:
    cur.execute('''
        CREATE TABLE IF NOT EXISTS auth
        (username TEXT, password TEXT, salt TEXT)
    ''')
except Exception as e:
    print("Error creating table:", e)

con.commit()
con.close()

# static salt ditambahkan setelah user memasukkan password
static_passwd_salt = b'%\x89\x08-\x82\xb9\xdf\x07\xbd\xbb\x88]\xa2q\x08\x90\xfb\x97\xa7R\xd5\xfc\xfda\x8b\xdd\xcb\x1c\x00\x84\x0e\xdc\xc4\xc0|1\x02-\xb0y\xff`0!gn\xa7\xdf)=\xba.w\x9f\x0b\x9a\xe6n\x9c\xa6\xc5S\xa0\xa0'

# mengembalikan data user
def query_user(user):
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("SELECT * FROM auth WHERE username=?", (user,))
    user_data = cur.fetchone()
    con.close()
    return user_data

# menambahkan pepper untuk keamanan tambahan 
peppers = [chr(i) for i in range(256)]

# menghasilkan pepper acak untuk password user
def rand_pepper():
    byte = os.urandom(1)
    bits = bin(int.from_bytes(byte, byteorder='big')).lstrip('0b')
    while len(bits) < 8:
        bits = '0' + bits
    return peppers[int(bits, 2)]

# memeriksa password user
def check_passwd(user, raw_passwd):
    user_data = query_user(user)
    if user_data is None:
        return False
    dbpasswd_hash = user_data[1]
    usersalt = user_data[2]
    for i in peppers:
        passwd = raw_passwd + i
        if hashlib.scrypt(password=passwd.encode("UTF-8"), salt=static_passwd_salt+usersalt, n=16, r=16, p=16).hex() == dbpasswd_hash:
            return True
    return False

# fungsi untuk menambahkan user baru
def get_password(prompt="Enter your password: "):
    print(prompt, end='', flush=True)
    password = []
    while True:
        char = msvcrt.getch()
        if char == b'\r':
            break
        elif char == b'\x08':
            if password:
                del password[-1]
                print("\b \b", end='', flush=True)
        else:
            password.append(char.decode('utf-8'))
            print('*', end='', flush=True)
    print()
    return ''.join(password)

def sign_up():
    print("\nTo create a new account, you must choose a unique username and password.\n")
    while True:
        print("(*Username length is between 4 to 12 character (including whitespace))")
        new_username = input("Enter your username: ")

        # Validasi username
        if not is_valid_username(new_username):
            print("Invalid username. Please choose another username.")
            continue

        if query_user(new_username):
            print("Username already exists. Please choose another username.")
        else:
            print("(*Password length minimum is 6 character and must contain at least one uppercase and one lowercase character, number, and special character)")
            new_password = get_password("Enter your password: ")

            # Validasi password
            if not is_valid_password(new_password):
                print("Invalid password. Please re-enter your credentials.")
                continue

            pass_confirm = get_password("Confirm your password: ")
            if pass_confirm == new_password:
                con = sqlite3.connect(db_path)
                otsalt = os.urandom(63)
                passwd = new_password + rand_pepper()
                cur = con.cursor()
                cur.execute("INSERT INTO auth VALUES (?, ?, ?)", (new_username, hashlib.scrypt(password=passwd.encode("UTF-8"), salt=static_passwd_salt + otsalt, n=16, r=16, p=16).hex(), otsalt))
                con.commit()
                con.close()
                system('cls')
                print("\nGreat! Your data has been confirmed. You can now log in with your new account.")
                break
            else:
                print("Passwords do not match. Please re-enter your credentials.")

# validasi panjang username
def is_valid_username(username):
    return 4 <= len(username) <= 12

#validasi panjang dan isi password user
def is_valid_password(password):
    return (
        len(password) >= 6 and
        any(c.isupper() for c in password) and
        any(c.islower() for c in password) and
        any(c.isdigit() for c in password) and
        any(not c.isalnum() for c in password)
    )

# log in user
# Dictionary untuk melacak percobaan gagal dan waktu terakhir
failed_login_attempts = {}

# Dictionary untuk melacak waktu blokir untuk setiap pengguna
blocked_users = {}

# Fungsi untuk menyimpan data pengguna yang terblokir ke dalam file
def save_blocked_users():
    with open("blocked_users.json", "w") as file:
        json.dump(blocked_users, file)

# Fungsi untuk memuat data pengguna yang terblokir dari file
def load_blocked_users():
    try:
        with open("blocked_users.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

# Inisialisasi data pengguna yang terblokir
blocked_users = load_blocked_users()

def log_in():
    username = input("username: ")
    
    # Periksa apakah pengguna diblokir
    if username in blocked_users:
        block_start_time, block_duration = blocked_users[username]
        current_time = time.time()
        if current_time - block_start_time < block_duration:
            remaining_time = int(block_start_time + block_duration - current_time)
            print(f"Your account ({username}) has been blocked, please try again later in {remaining_time} seconds.")
            time.sleep(4)
            system('cls')
            return register()

    if not query_user(username):
        system('cls')
        print("That user doesn't exist.\nplease re-insert valid username or make a new account\n")
        register()
    else:
        log_total = 4
        while log_total >= 0:
            password = get_password("Enter your password: ")
            if check_passwd(username, password) == True:
                print("You're logged in")
                system('cls')
                mainmenu(username)
                return username
            else:
                failed_login_attempts[username] = failed_login_attempts.get(username, 0) + 1

                # Ganda durasi blokir setiap kali pengguna terkena pemblokiran lagi
                if username in blocked_users:
                    block_start_time, block_duration = blocked_users[username]
                    block_duration *= 2
                else:
                    block_duration = 300  # Durasi blokir awal

                if failed_login_attempts[username] >= 5:
                    blocked_users[username] = (time.time(), block_duration)
                    save_blocked_users()  # Menyimpan data pengguna yang terblokir ke file
                    print("You have exceeded the credential input limit. Your account will be blocked for", block_duration, "seconds.")
                    print("Please use another account or make a new account")
                    time.sleep(4)
                    system('cls')
                    return register()

                if log_total > 1:
                    print("Incorrect password, please re-enter your password.")
                    log_total -= 1
                elif log_total == 1:
                    print("Incorrect password, please re-enter your password (last attempt).")
                    log_total -= 1


##################### BAGIAN FUNGSI UNTUK TAMPILAN AWAL DAN OPSI LOG IN/SIGN UP USER #####################

# user memasukkan identitas (sekaligus opsi untuk login/signup)
def register():
    header1 = "Welcome to JadwalMaster!"
    header2 = "Your personal program to help managing your daily schedule"
    length = len(header2) + 40
    print(f"""
+{'=' * length}+
|{header1.center(length)}|
|{header2.center(length)}|
+{'=' * length}+
""")
    logOption = input("Already have a registered account?\n1. Yes (Log In With Existing Account)\n2. No (Sign In New Account)\n3. Exit\nChoose One Option Above: ")
    if logOption == "1":
        log_in()
    elif logOption == "2":
        sign_up()
        register()
    elif logOption == "3":
        system('cls')
        closing = "See you! Thank you for using this program."
        len_close = len(closing) + 20
        print(f"""
    +{'=' * len_close}+
    |{closing.center(len_close)}|
    +{'=' * len_close}+
    """)
        time.sleep(3)
        exit()
    else:
        system('cls')
        print("Invalid input(Please insert between 1 or 2)\n")
        register()

##################### BAGIAN FUNGSI UNTUK MENU UTAMA USER #####################

#sapaan untuk user 
def greet_user(username):
    current_time = datetime.now()
    current_hour = current_time.hour

    if 1 <= current_hour < 12:
        return f"Look alive {username}! Hope you have a wonderful day."
    elif 12 <= current_hour < 18:
        return f"Good Afternoon {username}! Don't forget to grab your lunch!"
    else:
        return f"Good Evening {username}! Don't forget to brush your teeth before going to bed"

# Main Menu
def mainmenu(username):
   greeting = greet_user(username)
   line_length = len(greeting) + 40
   print(
    f"""
+{'=' * line_length}+
|{greeting.center(line_length)}|
+{'=' * line_length}+
""")
   while True:
    print("1. Add Event")
    print("2. View Schedule")
    print("3. Delete Event")
    print("4. Exit")
    choice = input("Enter your choice: ")

    #   menambahkan jadwal baru
    if choice == "1":
        create_schedule_db(username)
        event_time = input("Enter event time (yyyy-mm-dd HH:MM): ")
        if not is_valid_datetime(event_time):
            print("Invalid date and time format. Please use yyyy-mm-dd HH:MM format.")
        else:
            event_description = input("Enter event description: ")
            add_event(username, event_time, event_description)
            print("Event added successfully!")

    # menampilkan jadwal user
    elif choice == "2":
        schedule = view_schedule(username)
        system('cls')
        if not schedule:
            print("No events found. Your schedule is empty.")
        else:
            headers = ["Event Time", "Event Description"]
            schedule_data = [[datetime.strptime(event[0], '%Y-%m-%d %H:%M').strftime('%Y-%m-%d %H:%M'), event[1]] for event in schedule]
            table = tabulate(schedule_data, headers, tablefmt="grid")
            print(table)

    # menghapus jadwal
    elif choice == "3":
        schedule = view_schedule(username)
        if not schedule:
            print("No events found. Your schedule is empty.")
        else:
            print("Select the event to delete:")
            for i, event in enumerate(schedule):
                print(f"{i}. {datetime.strptime(event[0], '%Y-%m-%d %H:%M').strftime('%Y-%m-%d %H:%M')} - {event[1]}")
            event_index = int(input("Enter the event index: "))
            if 0 <= event_index < len(schedule):
                delete_event(username, event_index)
            else:
                print("Invalid event index. Please enter a valid index.")

    # kembali ke menu register
    elif choice == "4":
        system('cls')
        register()

    else:
        system('cls')
        print("Invalid input, please re-insert the option number\n")

##################### BAGIAN FUNGSI UNTUK KEPENTINGAN MANAJEMEN DB JADWAL USER #####################

# validasi tanggal dan waktu jadwal
def is_valid_datetime(date_string):
    try:
        datetime.strptime(date_string, '%Y-%m-%d %H:%M')
        return True
    except ValueError:
        return False
    
# membuat db baru untuk jadwal user
def create_schedule_db(username):
    db_name = f"schedule_{username}.db"
    con = sqlite3.connect(db_name)
    cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS schedule
                    (event_time text, event_description text)''')
    con.commit()
    con.close()

# menambah jadwal baru ke db
def add_event(username, event_time, event_description):
    db_name = f"schedule_{username}.db"
    con = sqlite3.connect(db_name)
    cur = con.cursor()
    cur.execute("INSERT INTO schedule VALUES (?, ?)", (event_time, event_description))
    con.commit()
    con.close()

# menampilkan jadwal user, diurutkan berdasarkan tanggal/waktu terdekat
def view_schedule(username):
    db_name = f"schedule_{username}.db"
    con = sqlite3.connect(db_name)
    cur = con.cursor()

    # memeriksa apakah tabel "schedule" ada dalam database
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schedule'")
    table_exists = cur.fetchone()

    if table_exists:
        cur.execute("SELECT * FROM schedule")
        events = cur.fetchall()
        con.close()

        if events:
            return sorted(events, key=lambda x: datetime.strptime(x[0], '%Y-%m-%d %H:%M'))
        else:
            print("Anda belum membuat jadwal.")
            return []
    else:
        con.close()
        print("Anda belum membuat jadwal.")
        return []
    
# menghapus jadwal user berdasarkan indeks
def delete_event(username, event_index):
    db_name = f"schedule_{username}.db"
    con = sqlite3.connect(db_name)
    cur = con.cursor()
    schedule = view_schedule(username)
    if 0 <= event_index < len(schedule):
        event_time = schedule[event_index][0]
        cur.execute("DELETE FROM schedule WHERE event_time=?", (event_time,))
        con.commit()
        system('cls')
        print(f"Event at {event_time} deleted successfully.")
    else:
        print("Invalid event index.")
    con.close()








register() 

# Edit Schedule
#   Add Schedule
#   Edit Schedule
#   Remove Schedule
# Remove Schedule
# Exit Program