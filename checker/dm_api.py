import requests
from checklib import BaseChecker
import hashlib

PORT = 8080
TIMEOUT = 5

class DMApi:
    def __init__(self, checker: BaseChecker, host=None, port=PORT):
        self.c = checker
        self.url = f'http://{host}:{port}'
    
    def ping(self):
        try:
            requests.get(self.url, timeout=TIMEOUT)
            return 1
        except Exception:
            return 0

    def register(self, nickname: str, tag: str, password: str) -> None:
        r = requests.post(f'{self.url}/register', json={'nickname': nickname, 'tag': tag, 'password': password})
        data = r.json()
        self.c.assert_eq(data['body'], 'User created successfully', 'Registration failed')
    
    def login(self, session: requests.Session, tag: str, password: str) -> requests.Session:
        r = session.post(f'{self.url}/login', json={'tag': tag, 'password': password})
        data = r.json()
        self.c.assert_eq(data['body'], 'Login successful', 'Login failed')
        return session

    def healthcheck(self) -> None:
        r = requests.get(f'{self.url}/health')
        data = r.json()
        self.c.assert_eq(data['status'], 'OK', 'Healthcheck failed')

    def get_users(self, session: requests.Session) -> None:
        r = session.get(f'{self.url}/users')
        data = r.json()
        self.c.assert_eq(data['status'], 'OK', 'Get users failed')
        self.c.assert_gt(len(data), 0, 'No users found')
    
    def start_convo(self, session: requests.Session, recipient_tag: str) -> None:
        r = session.post(f'{self.url}/start_convo', json={'recipient_tag': recipient_tag})
        data.json()
        self.c.assert_eq(data['status'], 'OK', 'Start convo failed')
        return data['conversation_id']

    def get_convos(self, session: requests.Session):
        r = session.get(f'{self.url}/convos')
        data = r.json()
        self.c.assert_eq(data['status'], 'OK', 'Get conversations failed')
        self.c.assert_gt(len(data), 0, 'No conversations found')
        return data
    
    def send_message(self, session: requests.Session, conversation_id: int, content: str) -> None:
        r = session.post(f'{self.url}/convo/{conversation_id}', json={'content': content})
        data = r.json()
        self.c.assert_eq(data['body'], 'Message sent', 'Send message failed')
    
    def get_messages(self, session: requests.Session, conversation_id: int):
        r = session.get(f'{self.url}/convo/{conversation_id}')
        data = r.json()
        self.c.assert_eq(data['status'], 'OK', 'Get messages failed')
        self.c.assert_gt(len(data), 0, 'No messages found')
    
    def backup(self, conversation_id: int) -> None:
        r = requests.post(f'{self.url}/backup/{conversation_id}')
        data = r.json()
        self.c.assert_eq(data['body'], 'Backup created', 'Backup failed')

    def download_backup(self, first_tag: str, second_tag: str) -> None:
        tags = [first_tag, second_tag].sort()
        joined = "_".join(sorted_tags)
        # Создаем хэш SHA256
        hasher = hashlib.sha256()
        hasher.update(joined.encode('utf-8'))
        backup_name = hasher.hexdigest() + '.zip'
        r = requests.get(f'{self.url}/backup/{backup_name}')
        data = r.json()
        self.c.assert_in(data['body'], f'{backup_name}', 'Download backup failed')

