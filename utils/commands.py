import re
import requests
import os
import shutil
from ddbb import connections as conns

APP_DIR = os.path.dirname(os.path.realpath(__file__))


class Command:

    def __init__(self, base_path='/root', list_files='', base_symb='~'):
        self.base_path  = base_path
        self.list_files = list_files
        self.base_symb  = base_symb

        self.cd_regex   = re.compile('cd\s([^\s]+)')
        self.curl_wget_regex = re.compile('(?:curl|wget)\s([^\s]*)')
        self.file_name_regex = re.compile('(?:curl|wget)\s(.*[/](.*))')

    def get_answer(self, cmd_received):
        if cmd_received.startswith('id'):
            return "\r\nuid=0(root) gid=0(root) groups=0(root)\r\n"

        elif cmd_received.startswith('ls'):
            return "\r\n{}\r\n".format(self.list_files)

        elif cmd_received.startswith('pwd'):
            return "\r\n{}\r\n".format(self.base_path)

        elif cmd_received.contains('curl') or cmd_received.contains('wget'):
            request_uri = self.curl_wget_regex.findall(cmd_received)
            if len(request_uri) > 0:
                try:
                    fullpath, file_name = self.file_name_regex.findall(cmd_received)[0]
                except Exception as e:
                    file_name = 'noname'

                try:
                    conns.add_sample(file_name)
                except Exception as e:
                    print(e)

                try:
                    r = requests.get(request_uri[1], stream=True)
                    if r.status_code == 200:
                        with open('../samples/' + file_name, 'wb') as f:
                            r.raw.decode_content = True
                            shutil.copyfileobj(r.raw, f)
                except Exception as e:
                    print(e)

            return "\r\n/connection timeout\r\n"

        elif cmd_received.startswith('cd '):
            matches = self.cd_regex.findall(cmd_received)
            if len(matches) > 0:
                self.base_symb = matches[0]

        elif cmd_received == '':
            return None

        else:
            return "\r\nbash: {}: command not found\r\n".format(cmd_received)

