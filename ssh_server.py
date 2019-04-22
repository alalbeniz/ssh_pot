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
if dbg: logger.debug(os.path.join(APP_DIR, "log/server.log"))
paramiko.util.log_to_file(os.path.join(APP_DIR, "log/server.log"))
logger = paramiko.util.get_logger('paramiko')

if dbg: logger.debug(os.path.join(APP_DIR, "keys/test_rsa.key"))
host_key = paramiko.RSAKey(filename=os.path.join(APP_DIR, "keys/test_rsa.key"))
# host_key = paramiko.DSSKey(filename='test_dss.key')

if dbg: logger.debug("Read key: " + u(hexlify(host_key.get_fingerprint())))

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
        logger.debug('Username: [{}], Password: [{}]'.format(username, password))
        if password != '':
            return paramiko.AUTH_SUCCESSFUL
        else:
            return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        logger.debug("Auth attempt with key: " + u(hexlify(key.get_fingerprint())))
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
#        logger.debug('direct_tcpip')
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
    logger.exception("*** Bind failed: " + str(e))
    sys.exit(1)

try:
    sock.listen(100)
    logger.debug("Listening for connection ...")
    client, addr = sock.accept()
    logger.debug("Connection from {}".format(addr))
except Exception as e:
    logger.exception("*** Listen/accept failed: " + str(e))
    sys.exit(1)

logger.debug("Got a connection!")

try:
    t = paramiko.Transport(client, gss_kex=DoGSSAPIKeyExchange)
    #t.local_version = 'SSH-2.0-OpenSSH'
    t.set_gss_host(socket.getfqdn(""))
    try:
        t.load_server_moduli()
    except:
        logger.debug("(Failed to load moduli -- gex will be unsupported.)")
        raise
    t.add_server_key(host_key)
    server = Server()
    try:
        t.start_server(server=server)
    except paramiko.SSHException:
        logger.debug("*** SSH negotiation failed.")
        sys.exit(1)

### OLD
# wait for auth
#    chan = t.accept(20)
#    if chan is None:
#        logger.debug("*** No channel.")
#        sys.exit(1)
#    logger.debug("Authenticated!")


#    server.event.wait(10)
#    if request.method == 'shell' and not server.event.is_set():
#    if not server.event.is_set():
#        logger.debug("*** Client never asked for a shell.")
#        sys.exit(1)
#    else:
#    elif request.method == 'direct_tcpip':
#        logger.debug('*** No shell direct_tcpip')
#        sys.exit(1)
#    else:
#        sys.exit(1)
#
#######
    # wait for auth
    ip_address = addr[0]

    chan = t.accept(30)

#    logger.debug('Username:[{}], Method:[{}], Pass:[{}]'.format(t.get_username(), t.server_object.get_method(), t.server_object.get_pass()))
    logger.debug('Username:[{}], Method:[{}], Pass:[]'.format(t.get_username(), t.server_object.get_method()))

    if chan is None:
        logger.debug('*** No channel.')
        sys.exit(1)

    logger.debug('Authenticated!')

    server.event.wait(10)
    if not server.event.is_set():
        logger.debug('*** Client never asked for a shell.')
        sys.exit(1)

    try:
#        logger.debug('Username:[{}], Method:[{}], Pass:[{}]'.format(t.get_username(), t.server_object.get_method(), t.server_object.get_pass()))

#        chan.send("{}@OpenWrt:~#".format(t.get_username()))
#        f = chan.makefile("rU")
#        command = f.readline().strip("\r\n")
##
#        logger.debug('Command:[{}]'.format(command))
#        final_command = command + '\r\n'

#        try:
#            ip_address = addr[0]
##            sqlconn.add_connection(t.get_username(), t.server_object.get_pass(), command)#, t.server_object.)
##            sqlconn.add_connection(t.get_username(), t.server_object.get_pass(), ip_address)#, t.server_object.)
#            sqlconn.add_connection(t.get_username(), t.server_object.get_pass(), ip_address, command)#, t.server_object.)
#        except Exception as e:
#            logger.debug("*** Caught exception: " + str(e.__class__) + ": " + str(e))
#            traceback.logger.debug_exc()

        command_parser = commands.Command()
        final_command = ''
        for i in range(10):
            try:
                chan.send("{}@OpenWrt:{}#".format(t.get_username(), command_parser.base_symb))
                f = chan.makefile("rU")
                command = f.readline().strip("\r\n")
            except OSError as e:
                break

            command_answer = command_parser.get_answer(command)
            if not command_answer:
                break
            chan.send(command_answer)

            final_command = final_command + command + '\r\n'
            logger.debug('Command:[{}]'.format(command))

#        sqlconn.add_connection(t.get_username(), t.server_object.get_pass(), ip_address)#, t.server_object.)
    except Exception as e:
        logger.exception("*** Caught exception: " + str(e.__class__) + ": " + str(e))

    try:
        sqlconn.add_connection(t.get_username(), t.server_object.get_pass(), ip_address, final_command, t.remote_version)#, t.server_object.)
    except Exception as e:
        logger.exception("*** Caught exception: " + str(e.__class__) + ": " + str(e))


    chan.close()
    t.close()

except Exception as e:
    logger.exception("*** Caught exception: " + str(e.__class__) + ": " + str(e))
    try:
        t.close()
    except:
        pass
sys.exit(1)


