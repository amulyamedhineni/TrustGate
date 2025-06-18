import hashlib
import platform
import uuid
import requests

SERVER_URL = "http://127.0.0.1:5000/register-device"

def get_device_id():
    data = platform.node() + platform.system() + platform.processor() + str(uuid.getnode())
    return hashlib.sha256(data.encode()).hexdigest()

def main():
    username = input("Enter your username: ")
    device_id = get_device_id()

    response = requests.post(SERVER_URL, json={
        "username": username,
        "device_id": device_id
    })

    print(response.json())

if __name__ == "__main__":
    main()
