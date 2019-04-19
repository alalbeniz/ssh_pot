#!/usr/bin/env python

from ddbb import connections as sqlconn
from utils import commands

from binascii import hexlify
import os
import socket
import sys
import threading
import traceback

import paramiko
from paramiko.py3compat import b, u, decodebytes

dbg = False

APP_DIR = os.path.dirname(os.path.realpath(__file__))

# setup logging
if dbg: print(os.path.join(APP_DIR, "log/server.log"))
paramiko.util.log_to_file(os.path.join(APP_DIR, "log/server.log"))

if dbg: print(os.path.join(APP_DIR, "keys/test_rsa.key"))
host_key = paramiko.RSAKey(filename=os.path.join(APP_DIR, "keys/test_rsa.key"))
# host_key = paramiko.DSSKey(filename='test_dss.key')

if dbg: print("Read key: " + u(hexlify(host_key.get_fingerprint())))

class Server(paramiko.ServerInterface):
    __pass    = None
#    __ssh_key = None
    __method  = None

    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.__method = 'pass'
        self.__pass   = password
        print('Username: {}, Password: {}'.format(username, password))
        if password != '':
            return paramiko.AUTH_SUCCESSFUL
        else:
            return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        print("Auth attempt with key: " + u(hexlify(key.get_fingerprint())))
        self.__method = 'key'
        self.__pass   = key
        return paramiko.AUTH_SUCCESSFUL

    def enable_auth_gssapi(self):
        return True

    def get_allowed_auths(self, username):
        #return "gssapi-keyex,gssapi-with-mic,password,publickey"
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

#    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
#        print('direct_tcpip')
#        #request.method = 'direct_tcpip'
#        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True

    def get_pass(self):
        return self.__pass

    def get_method(self):
        return self.__method

DoGSSAPIKeyExchange = True

# now connect
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", 13022))
except Exception as e:
    print("*** Bind failed: " + str(e))
    traceback.print_exc()
    sys.exit(1)

try:
    sock.listen(100)
    print("Listening for connection ...")
    client, addr = sock.accept()
    print("Connection from {}".format(addr))
except Exception as e:
    print("*** Listen/accept failed: " + str(e))
    traceback.print_exc()
    sys.exit(1)

print("Got a connection!")

try:
    t = paramiko.Transport(client, gss_kex=DoGSSAPIKeyExchange)
    #t.local_version = 'SSH-2.0-OpenSSH'
    t.set_gss_host(socket.getfqdn(""))
    try:
        t.load_server_moduli()
    except:
        print("(Failed to load moduli -- gex will be unsupported.)")
        raise
    t.add_server_key(host_key)
    server = Server()
    try:
        t.start_server(server=server)
    except paramiko.SSHException:
        print("*** SSH negotiation failed.")
        sys.exit(1)

### OLD
# wait for auth
#    chan = t.accept(20)
#    if chan is None:
#        print("*** No channel.")
#        sys.exit(1)
#    print("Authenticated!")


#    server.event.wait(10)
#    if request.method == 'shell' and not server.event.is_set():
#    if not server.event.is_set():
#        print("*** Client never asked for a shell.")
#        sys.exit(1)
#    else:
#    elif request.method == 'direct_tcpip':
#        print('*** No shell direct_tcpip')
#        sys.exit(1)
#    else:
#        sys.exit(1)
#
#######
    # wait for auth
    ip_address = addr[0]

    chan = t.accept(30)
    print('Username:[{}], Method:[{}], Pass:[{}]'.format(t.get_username(), t.server_object.get_method(), t.server_object.get_pass()))
    if chan is None:
        print('*** No channel.')
        sys.exit(1)

    print('Authenticated!')

    server.event.wait(10)
    if not server.event.is_set():
        print('*** Client never asked for a shell.')
        sys.exit(1)

    try:
        print('Username:[{}], Method:[{}], Pass:[{}]'.format(t.get_username(), t.server_object.get_method(), t.server_object.get_pass()))

        chan.send("{}@OpenWrt:~#".format(t.get_username()))
        f = chan.makefile("rU")
        command = f.readline().strip("\r\n")
#
        print('Command:[{}]'.format(command))
        final_command = command + '\r\n'
#        try:
#            ip_address = addr[0]
##            sqlconn.add_connection(t.get_username(), t.server_object.get_pass(), command)#, t.server_object.)
##            sqlconn.add_connection(t.get_username(), t.server_object.get_pass(), ip_address)#, t.server_object.)
#            sqlconn.add_connection(t.get_username(), t.server_object.get_pass(), ip_address, command)#, t.server_object.)
#        except Exception as e:
#            print("*** Caught exception: " + str(e.__class__) + ": " + str(e))
#            traceback.print_exc()

        command_parser = commands.Command()



        # base_path = '/root'
        # list_files= ''
        # base_symb = '~'

        for i in range(10):
            command_answer = command_parser.get_answer(command)
            chan.send(command_answer)

            # if command.startswith('id'):
            #     chan.send("\r\nuid=0(root) gid=0(root) groups=0(root)\r\n")
            # elif command.startswith('ls'):
            #     chan.send("\r\n{}\r\n".format(list_files))
            # elif command.startswith('pwd'):
            #     chan.send("\r\n{}\r\n".format(base_path))
            # elif command.startswith('curl'):
            #     chan.send("\r\n/connection timeout\r\n")
            # elif command.startswith('wget'):
            #     chan.send("\r\n/connection timeout\r\n")
            # elif command.startswith('cd '):
            #     base_symb = '/tmp'
            # elif command == '':
            #     pass
            # else:
            #     chan.send("\r\nbash: {}: command not found\r\n".format(command))

            final_command = final_command + command + '\r\n'
            print('Command:[{}]'.format(command))

            try:
                chan.send("{}@OpenWrt:{}#".format(t.get_username(), command_parser.base_symb))
                f = chan.makefile("rU")
                command = f.readline().strip("\r\n")
            except OSError as e:
                break

#        sqlconn.add_connection(t.get_username(), t.server_object.get_pass(), ip_address)#, t.server_object.)
        sqlconn.add_connection(t.get_username(), t.server_object.get_pass(), ip_address, final_command, t.remote_version)#, t.server_object.)
    except Exception as e:
        sqlconn.add_connection(t.get_username(), t.server_object.get_pass(), ip_address, final_command, t.remote_version)#, t.server_object.)
        print("*** Caught exception: " + str(e.__class__) + ": " + str(e))
        traceback.print_exc()

    chan.close()
    t.close()

except Exception as e:
    print("*** Caught exception: " + str(e.__class__) + ": " + str(e))
    traceback.print_exc()
    try:
        t.close()
    except:
        pass
sys.exit(1)


