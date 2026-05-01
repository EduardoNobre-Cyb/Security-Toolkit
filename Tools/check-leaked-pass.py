import requests
import hashlib

pwd = input("Check password: ")

url = "https://api.pwnedpasswords.com/range/"

hashed = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
prefix, suffix = hashed[:5], hashed[5:]

response = requests.get(f"{url}{prefix}")

if suffix in response.text:
    print("Password has been leaked!")
else:
    print("Password is safe.")
