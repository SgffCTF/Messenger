import requests
from checklib import BaseChecker
import hashlib

PORT = 6969
TIMEOUT = 5

class MessengerApi:
    def __init__(self, checker: BaseChecker, host=None, port=PORT):
        self.c = checker
        self.session = requests.Session()
        self.url = f'http://{host}:{port}'

    # def ping(self):
    #     try:
    #         r = requests.get(f"{self.url}/health", timeout=TIMEOUT)
    #         self.c.assert_eq(r.status_code, 200, "Ping failed")
    #         return 1
    #     except Exception as e:
    #         self.c.assert_(False, f"Ping failed: {str(e)}")
    #         return 0

    def register(self, nickname: str, tag: str, password: str) -> None:
        r = self.session.post(url=f'{self.url}/register', json={'nickname': nickname, 'tag': tag, 'password': password})

        self.c.assert_eq(r.status_code, 201, "Registration failed")
        self.c.assert_eq("User created successfully", r.text, "Registration response does not contain 'User created succesfully'")

    def login(self, tag: str, password: str) -> None:
        r = self.session.post(url=f'{self.url}/login', json={'tag': tag, 'password': password})

        self.c.assert_eq(r.status_code, 200, "Login failed")
        self.c.assert_eq("Login successful", r.text, "Login response does not 'Login succesful'")

    def healthcheck(self) -> None:
        r = requests.get(url=f'{self.url}/health')

        self.c.assert_eq(r.status_code, 200, "Healthcheck failed")
        self.c.assert_in("Healthy", r.text, "Healthcheck response does not contain status")

    def get_users(self) -> None:
        r = self.session.get(url=f'{self.url}/users')

        self.c.assert_eq(r.status_code, 200, "Get users failed")
        self.c.assert_(isinstance(r.json(), list), "Get users response is not a list")
        for user in r.json():
            self.c.assert_in("last_seen", user, "User object does not contain last seen info")
            self.c.assert_in("nickname", user, "User object does not contain nickname")
            self.c.assert_in("tag", user, "User object does not contain tag")

    def start_convo(self, recipient_tag: str) -> str:
        r = self.session.post(url=f'{self.url}/start_convo', json={'recipient_tag': recipient_tag})

        self.c.assert_(r.status_code == 201 or r.status_code == 200, "Start conversation failed")
        self.c.assert_in("conversation_id", r.json(), "Start conversation response does not contain conversation_id")
        return r.json()["conversation_id"]

    def get_convos(self):
        r = self.session.get(url=f'{self.url}/convos')

        self.c.assert_eq(r.status_code, 200, "Get conversations failed")
        self.c.assert_(isinstance(r.json(), list), "Get conversations response is not a list")
        for convo in r.json():
            self.c.assert_in("id", convo, "Conversation object does not contain id")
            self.c.assert_in("participant_tag", convo, "Conversation object does not contain participant_id")
            self.c.assert_in("participant_nickname", convo, "Conversation object does not contain participant_nickname")

    def send_message(self, conversation_id: int, content: str) -> None:
        r = self.session.post(url=f'{self.url}/convo/{conversation_id}', json={'content': content})

        self.c.assert_eq(r.status_code, 201, "Send message failed")
        self.c.assert_in("Message sent", r.text, "Send message response does not 'Message Sent'")

    def get_messages(self, conversation_id: int):
        r = self.session.get(url=f'{self.url}/convo/{conversation_id}')

        self.c.assert_eq(r.status_code, 200, "Get messages failed")
        self.c.assert_in("messages", r.json(), "Get messages response does not contain messages")
        self.c.assert_(isinstance(r.json()["messages"], list), "Messages is not a list")
        response = r.json()
        self.c.assert_in("messages", response, "Message object does not contain message")
        self.c.assert_in("participant_nickname", response, "Message object does not contain partipiciant nickname")
        return r.json()["messages"]

    def backup(self, conversation_id: int) -> None:
        r = self.session.post(url=f'{self.url}/backup/{conversation_id}')
        self.c.assert_eq(r.status_code, 200, "Backup creation failed")
        self.c.assert_in("Backup created", r.text, "Backup response does not contain 'Backup created'")

    def download_backup(self, first_tag: str, second_tag: str) -> None:
        sorted_tags = sorted([first_tag, second_tag])
        joined = "_".join(sorted_tags)
        hasher = hashlib.sha256()
        hasher.update(joined.encode('utf-8'))
        backup_name = hasher.hexdigest() + '.zip'
        r = self.session.get(url=f'{self.url}/backup/{backup_name}')

        self.c.assert_eq(r.status_code, 200, "Backup download failed")
        self.c.assert_(r.content, "Backup content is empty")
