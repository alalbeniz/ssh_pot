import re
import requests
import os
import shutil
import traceback
import paramiko

from ddbb import connections as conns

APP_DIR = os.path.dirname(os.path.realpath(__file__))

logger = paramiko.util.get_logger('paramiko')


class Command:

    def __init__(self, base_path='/root', list_files='', base_symb='~'):
        self.base_path  = base_path
        self.list_files = list_files
        self.base_symb  = base_symb

        self.cd_regex   = re.compile('cd\s([^\s]+)')
        self.curl_wget_regex = re.compile('(?:curl|wget)\s([^\s]*)')
        self.file_name_regex = re.compile('(?:curl|wget)\s(.*[/](.*))')

    def get_answer(self, cmd_received):
        try:
            if cmd_received.startswith('id'):
                return "\r\nuid=0(root) gid=0(root) groups=0(root)\r\n"
    
            elif cmd_received.startswith('ls'):
                return "\r\n{}\r\n".format(self.list_files)
    
            elif cmd_received.startswith('pwd'):
                return "\r\n{}\r\n".format(self.base_path)

            elif cmd_received.startswith('exit'):
                return None
    
            elif 'curl' in cmd_received or 'wget' in cmd_received:
                request_uri = self.curl_wget_regex.findall(cmd_received)
                if request_uri and len(request_uri) > 0:
                    try:
                        fullpath, file_name = self.file_name_regex.findall(cmd_received)[0]
                        logger.info('URI: [{}], Sample: [{}]'.format(fullpath, file_name))
                    except Exception as e:
                        file_name = 'noname'
    
                    try:
                        conns.add_sample(file_name)
                    except Exception as e:
                        logger.exception('*** Caught exception')
    
                    try:
                        logger.info(request_uri)
                        r = requests.get(request_uri[0], stream=True)
                        if r.status_code == 200:
                            exists = os.path.isfile(APP_DIR + '/' + '../samples/' + file_name)
                            i = 0
                            final_path = APP_DIR + '/' + '../samples/' + file_name
                            while exists:
                                i+=1
                                exists = os.path.isfile(APP_DIR + '/' + '../samples/' + file_name + ".%s" % i)
                                final_path = APP_DIR + '/' + '../samples/' + file_name + ".%s" % i

                            try:
                                with open(final_path, 'wb') as f:
                                    r.raw.decode_content = True
                                    shutil.copyfileobj(r.raw, f)
                            except Exception as e:
                                logger.exception('Unable to write to path')

                    except Exception as e:
                        logger.exception('*** Caught exception')
    
                return "\r\nconnection timeout\r\n"
    
            elif cmd_received.startswith('cd '):
                matches = self.cd_regex.findall(cmd_received)
                if matches and len(matches) > 0:
                    if matches[0].startswith('/'):
                        self.base_symb = matches[0]
                        self.base_path = matches[0]
                    else:
                        self.base_symb = self.base_symb + '/' + matches[0]
                        self.base_path = self.base_path + '/' + matches[0]
                return '\r\n'
    
            elif cmd_received == '':
                return '\r\n'
    
            else:
                if ' ' in cmd_received:
                    clean_cmd = cmd_received.split(' ')
                    return "\r\nbash: {}: command not found\r\n".format(clean_cmd[0])
                else:
                    return "\r\nbash: {}: command not found\r\n".format(cmd_received)
        except Exception:
            logger.exception('*** Caught exception')


