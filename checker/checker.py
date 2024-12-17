#!/usr/bin/env -S python3

import sys
import requests
import random
import messenger_api
from checklib import *
from checklib import status


class Checker(BaseChecker):
    vulns: int = 1
    timeout: int = 20
    uses_attack_data: bool = True
    
    user_agents = [f'python-requests/2.{x}.0' for x in range(15, 28)]
    
    def __init__(self, *args, **kwargs):
        super(Checker, self).__init__(*args, **kwargs)
        self.api = messenger_api.MessengerApi(self, self.host)
    
    def check(self):
        # ping = self.api.healthcheck()
        # if not ping:
        #     self.cquit(Status.DOWN, "Failed to Connect")

        # healthcheck
        self.api.healthcheck()

        # check register, login
        f_nick, f_tag, f_pass = rnd_username(), rnd_string(16), rnd_password()
        s_nick, s_tag, s_pass = rnd_username(), rnd_string(16), rnd_password()

        self.api.register(f_nick, f_tag, f_pass)
        self.api.login(f_tag, f_pass)
        self.api.register(s_nick, s_tag, s_pass)
        self.api.login(s_tag, s_pass)
        self.api.get_users()
        
        # check create conversation
        convo_id = self.api.start_convo(f_tag)
        self.api.get_convos()

        # check send message
        content = rnd_string(12)
        self.api.send_message(convo_id, content)
        
        # check get conversation
        self.api.get_messages(convo_id)
        
        # check backups
        self.api.backup(convo_id)
        self.api.download_backup(f_tag, s_tag)
        self.cquit(Status.OK)
    
    def put(self, flag_id: str, flag: str, vuln: str):
        # ping = self.api.ping()
        # if not ping:
        #     self.cquit(Status.DOWN, "Failed to Connect")
        
        f_nick, f_tag, f_pass = rnd_username(), rnd_string(16), rnd_password()
        s_nick, s_tag, s_pass = rnd_username(), rnd_string(16), rnd_password()

        self.api.register(f_nick, f_tag, f_pass)
        self.api.login(f_tag, f_pass)
        self.api.register(s_nick, s_tag, s_pass)
        self.api.login(s_tag, s_pass)

        convo_id = self.api.start_convo(f_tag)
        self.api.send_message(convo_id, flag)
        private_flag_id = f"{f_tag}:{f_pass}:{s_tag}"
        public_flag_id = f"{f_nick}:{s_nick}:{convo_id}"
        self.cquit(Status.OK, public=public_flag_id, private=private_flag_id)
    
    def get(self, flag_id: str, flag: str, vuln: str):
        f_tag, f_pass, s_tag = flag_id.split(":")
        self.api.login(f_tag, f_pass)
        convo_id = self.api.start_convo(s_tag)
        convo_info = self.api.get_messages(convo_id)
        for message in convo_info:
            if message["content"] == flag:
                self.cquit(Status.OK)
        self.cquit(Status.CORRUPT, "Failed to get flag")

if __name__ == '__main__':
    c = Checker(sys.argv[2])
    try:
        c.action(sys.argv[1], *sys.argv[3:])
    except c.get_check_finished_exception() as e:
        cquit(status.Status(c.status), c.public, c.private)