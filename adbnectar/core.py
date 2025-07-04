#!/usr/bin/env python3

from argparse import ArgumentParser
from datetime import datetime, timezone
import threading
import binascii
import hashlib
import logging
import socket
import struct
import queue as Queue
import json
import time
import random
import re
import sys
import os
import requests
from requests import RequestException
from urllib.parse import urlparse

#package imports
from .config import CONFIG, OUTPUT_PLUGINS
from .responses import cmd_responses
from . import protocol
from . import outputs

__version__ = '1.00'

MAX_READ_COUNT = 4096 * 4096
# sleep 1 second after each empty packets, wait 1 hour in total
MAX_EMPTY_PACKETS = 360
MAX_SIMULATED_NETWORK_DELAY_IN_SECONDS = 10 # How many seconds to be used as the max for the random generator when simulating network delay.
IDLE_TIMEOUT = 300 # seconds

HTTP_USER_AGENT = CONFIG.get('honeypot', 'http_useragent')

DEVICE_ID = CONFIG.get('honeypot', 'device_id')
log_q = Queue.Queue()
download_q = Queue.Queue()

class OutputLogger():
    def __init__(self, log_q):
        self.log_q = log_q
        self.debug('OutputLogger init!')

    def debug(self, message):
        level = logging.DEBUG
        self.log_q.put((message, level))

    def info(self, message):
        level = logging.INFO
        self.log_q.put((message, level))

    def error(self, message):
        level = logging.ERROR
        self.log_q.put((message, level))

    def write(self, message):
        self.log_q.put(message)

logger = OutputLogger(log_q)


class UrlDownloader(threading.Thread):
    
    def __init__(self):
        logger.debug("Creating UrlDownloader!")
        threading.Thread.__init__(self)
        self.session = requests.session()
        self.session.headers.update({'User-Agent': HTTP_USER_AGENT})
        if(CONFIG.get('honeypot', 'http_proxy', fallback='') != ''):
            proxy = CONFIG.get('honeypot', 'http_proxy')
            logger.debug(f"Using HTTP Proxy: {proxy}")
            self.session.proxies.update({
                'http': proxy,
                'https': proxy
            })
        self.process = True

    def run(self):
        logger.debug("Starting UrlDownloader!")
        DL_DIR = CONFIG.get('honeypot', 'download_dir')
        HTTP_TIMEOUT = CONFIG.getint('honeypot', 'http_timeout', fallback=45)
        USE_VT = CONFIG.getboolean('virustotal', 'submit_files_to_VT', fallback=False)
        if DL_DIR and not os.path.exists(DL_DIR):
            os.makedirs(DL_DIR) 
        while not download_q.empty() or self.process:
            try:
                url, session = download_q.get(timeout=.1)
                filename = os.path.basename(urlparse(url).path)
            except Queue.Empty:
                continue
            try:
                response = self.session.get(url, timeout=HTTP_TIMEOUT)
            except (OSError, RequestException):
                logger.debug(f"Failed to Download {url}")
                continue

            data = response.content
            if (data == None) or  (len(data)==0):
                continue
            sha256sum = hashlib.sha256(data).hexdigest()
            fn = '{}.raw'.format(sha256sum)
            fp = os.path.join(DL_DIR, fn)

            logger.info('File downloaded: {}, name: {}, bytes: {}'.format(fp, filename, len(data)))
            obj = {
                "eventid": "adbnectar.session.file_download",
                "src_url": url,
                "shasum": sha256sum,
                "outfile": fp,
                "filename": filename,
                "session" : session
            }
            #Don't overwrite the file if it already exists
            if not os.path.exists(fp):
                with open(fp, 'wb') as file_out:
                    file_out.write(response.content)
                    file_out.flush()
            #Report on downloaded file after write and close.
            self.report(obj)
            
            if(USE_VT):
                # If the key isn't defined in the config, check the environment variable.
                VT_API_KEY = CONFIG.get('virustotal', 'api_key', fallback=os.environ.get('VIRUSTOTAL_API_KEY', None))
                if VT_API_KEY:
                    try:
                        vt_response = outputs.submit_sample_to_VT(fp, VT_API_KEY)
                        logger.info(f"VirusTotal response for {filename}({sha256sum}): {vt_response}")
                    except Exception as e:
                        logger.error(f"Failed to submit {filename}({sha256sum}) to VirusTotal: {e}")
                else:
                    logger.warning(f"VirusTotal API key is not set, skipping submission of {filename}({sha256sum}).")

    def stop(self):
        self.process = False

    def report(self, obj):
        obj['timestamp'] = datetime.now(timezone.utc).isoformat() + 'Z'
        obj['unixtime'] = int(time.time())
        obj['sensor'] = CONFIG.get('honeypot', 'hostname')
        logger.debug("Placing {} on log_q".format(obj))
        logger.write(obj)

class OutputWriter(threading.Thread):
    def __init__(self):
        logger.debug("Creating OutputWriter!")
        threading.Thread.__init__(self)
        self.process = True
        self.output_writers = []
        for output in OUTPUT_PLUGINS:
            output_writer = __import__('adbnectar.outputs.{}'\
                    .format(output), globals(), locals(), ['output']).Output()
            self.output_writers.append(output_writer)

    def run(self):
        logger.debug("Starting OutputWriter!")
        while not log_q.empty() or self.process:
            try:
                log = log_q.get(timeout=.1)
            except Queue.Empty:
                continue
            if type(log) is tuple:
                self.log(*log)
            else:
                self.write(log)
            log_q.task_done()

    def stop(self):
        self.process = False

    def write(self, log):
        for writer in self.output_writers:
            writer.write(log)

    def log(self, log, level):
        first_logger = self.output_writers[0]
        if first_logger.__name__ == 'output_log':
            first_logger.write(log, level)

class ADBConnection(threading.Thread):
    def __init__(self, conn, addr):
        threading.Thread.__init__(self)
        self.conn = conn
        self.addr = addr
        self.http_download = CONFIG.getboolean('honeypot','http_download', fallback=False)
        self.url_regex = re.compile(r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))")
        self.run()
        
    def generate_network_delay(self):
        #Generate a random network delay between 0 and MAX_SIMULATED_NETWORK_DELAY_IN_SECONDS seconds.
        return random.uniform(0, MAX_SIMULATED_NETWORK_DELAY_IN_SECONDS + 1)

    def report(self, obj):
        obj['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        obj['unixtime'] = int(time.time())
        obj['session'] = self.session
        obj['sensor'] = CONFIG.get('honeypot', 'hostname')
        logger.debug("Placing {} on log_q".format(obj))
        logger.write(obj)

    def run(self):
        logger.debug("Processing new connection!")
        self.process_connection()

    def send_message(self, command, arg0, arg1, data):
        if(CONFIG.getboolean('honeypot', 'simulate_network_delay', fallback=False)):
            # Simulate network delay if configured
            delay = self.generate_network_delay()
            logger.debug(f"Simulating network delay of {delay:.2f} seconds for command {command}")
            time.sleep(delay)
        newmessage = protocol.AdbMessage(command, arg0, arg1, data)
        logger.debug('sending: {}'.format(newmessage))
        self.conn.sendall(newmessage.encode())

    def send_twice(self, command, arg0, arg1, data):
        self.send_message(command, arg0, arg1, data)
        self.send_message(command, arg0, arg1, data)

    def recv_data(self):
        debug_content = bytes()
        empty_packets = 0
        self.conn.settimeout(1.0) # Set socket timeout to 1 second
        try:
            command = self.conn.recv(4)
            if not command:
                empty_packets += 1
                if empty_packets > MAX_EMPTY_PACKETS:
                    return None
                # wait for more data
                time.sleep(0.1)
                return None
            empty_packets = 0
            arg1 = self.conn.recv(4)
            arg2 = self.conn.recv(4)
            data_length_raw = self.conn.recv(4)
            data_length = struct.unpack('<L', data_length_raw)[0]
            data_crc = self.conn.recv(4)
            magic = self.conn.recv(4)

            data_content = bytes()

            if data_length > 0:
                # prevent reading the same stuff over and over again from some other attackers and locking the honeypot
                # max 1 byte read 64*4096 times (max packet length for ADB)
                read_count = 0

                while len(data_content) < data_length and read_count < MAX_READ_COUNT:
                    read_count += 1
                    # don't overread the content of the next data packet
                    bytes_to_read = data_length - len(data_content)
                    data_content += self.conn.recv(bytes_to_read)
                    time.sleep(0.1)
            # check integrity of read data
            if len(data_content) < data_length:
                logger.error("data content length is greater than data_length, corrupt data!")
                # corrupt content, abort the self.connection (probably not an ADB client)
                data = None
            else:
                # assemble a full data packet as per ADB specs
                data = command + arg1 + arg2 + data_length_raw + data_crc + magic + data_content
        except socket.timeout:
            logger.debug("Socket timeout - no data received")
            return None
        except Exception as e:
            logger.info("Connection reset by peer.")
            raise EOFError
        return data

    def parse_data(self, data):
        try:
            message = protocol.AdbMessage.decode(data)[0]
            logger.debug("decoded message {}".format(message))
            string = str(message)
            if len(string) > 96:
                logger.debug('<<<<{} ...... {}'.format(string[0:64], string[-32:]))
            else:
                logger.debug('<<<<{}'.format(string))
            return message
        except Exception as e:
            logger.error(e)
            # don't print anything, a lot of garbage coming in usually, just drop the connection
            raise 
        #return None

    def dump_file(self, f):
        DL_DIR = CONFIG.get('honeypot', 'download_dir')
        if DL_DIR and not os.path.exists(DL_DIR):
            os.makedirs(DL_DIR)
        sha256sum = hashlib.sha256(f['data']).hexdigest()
        fn = '{}.raw'.format(sha256sum)
        fp = os.path.join(DL_DIR, fn)
        logger.info('File uploaded: {}, name: {}, bytes: {}'.format(fp, f['name'], len(f['data'])))
        obj = {
            "eventid": "adbnectar.session.file_upload",
            "src_ip": self.addr[0],
            "shasum": sha256sum,
            "outfile": fp,
            "filename": f['name']
        }
        self.report(obj)
        #Don't overwrite the file if it already exists
        if not os.path.exists(fp):
            with open(fp, 'wb') as file_out:
                file_out.write(f['data'])
                

    def recv_binary_chunk(self, message, data, f):
        if len(message.data) == 0:
            self.sending_binary = False
            return
        logger.debug("Received binary chunk of size: {}".format(len(message.data)))
        # look for that shitty DATAXXXX where XXXX is the length of the data block that's about to be sent
        # (i.e. DATA\x00\x00\x01\x00)
        if message.command == protocol.CMD_WRTE and bytes('DATA', "utf-8") in message.data:
            data_index = message.data.index(bytes('DATA', "utf-8"))
            payload_fragment = message.data[:data_index] + message.data[data_index + 8:]
            f['data'] += payload_fragment
        elif message.command == protocol.CMD_WRTE:
            f['data'] += message.data

        # truncate
        if bytes('DONE', "utf-8") in message.data:
            f['data'] = f['data'][:-8]
            self.sending_binary = False
            self.dump_file(f)

            # ADB has a shitty state machine, sometimes we need to send duplicate messages
            self.send_twice(protocol.CMD_WRTE, 2, message.arg0, 'OKAY')
            self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')

        if message.command != protocol.CMD_WRTE:
            f['data'] += data

        self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')

        return f


    def recv_binary(self, message, f):
        logger.info("Receiving binary file...")
        self.sending_binary = True
        predata = message.data.split(bytes('DATA', "utf-8"))[0]
        if predata:
            parts = predata.split(bytes(',', "utf-8"))
            prefix = bytes('\x00\x00\x00', "utf-8")
            if prefix in parts[0]:
                name_parts = parts[0].split(prefix)
                if len(name_parts) == 1:
                    f['name'] = str(name_parts[0], "utf-8")
                else:
                    f['name'] = str(name_parts[1], "utf-8")
            else:
                f['name'] = str(parts[0], "utf-8")
            #filename = parts[0].split('\x00\x00\x00')[1]

        # if the message is really short, wrap it up
        if bytes('DONE', "utf-8") in message.data[-8:]:
            self.sending_binary = False
            f['data'] = message.data.split(bytes('DATA', "utf-8"))[1][4:-8]
            self.send_twice(protocol.CMD_WRTE, 2, message.arg0, 'OKAY')
            self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
            self.dump_file(f)
        else:
            f['data'] = message.data.split(bytes('DATA', "utf-8"))[1][4:]

        self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')

        return f

    def recv_shell_cmd(self, message):
        logger.debug("Entering recv_shell_cmd")
        self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')

        #command will be 'shell:cd /;wget http://someresource.com/test.sh\x00'
        #Remove first six chars and last null byte.
        cmd = str(message.data[6:-1], "utf-8")
        logger.info("shell command is {}, len {}".format(cmd, len(cmd)))
        if cmd in cmd_responses:
            response = cmd_responses[cmd]
        else:
            response = f"{cmd}: command not found" # Fake the default response for unknown commands in the case of lacking implementation.

        # change the WRTE contents with whatever you'd like to send to the attacker
        self.send_message(protocol.CMD_WRTE, 2, message.arg0, response)
        self.send_message(protocol.CMD_CLSE, 2, message.arg0, '')
        # print the shell command that was sent
        # also remove trailing \00
        logger.info('{}\t{}'.format(self.addr[0], message.data[:-1]))
        obj = {
            "eventid": "adbnectar.command.input",
            "input": cmd,
            "src_ip": self.addr[0],
        }
        self.report(obj)
        if(self.http_download):
            for url in self.url_regex.findall(cmd):
                download_q.put((url[0],self.session),timeout=.1)

    def process_connection(self):
        start = time.time()
        self.session = str(binascii.hexlify(os.urandom(6)), "utf-8")
        localip = socket.gethostbyname(socket.gethostname())
        logger.info('{} connection start ({})'.format(self.addr[0], self.session))
        obj = {
            "eventid": "adbnectar.session.connect",
            "src_ip": self.addr[0],
            "src_port": self.addr[1],
            "dst_ip": localip,
            "dst_port": CONFIG.get('honeypot', 'port'),
        }
        self.report(obj)

        states = []
        self.sending_binary = False
        f = {"name": "", "data": ""}
        # Track the last active time for idle timeout
        last_active_time = time.time()
        filename = 'unknown'
        closedmessage = 'Connection closed'
        while True:
            try:
                data = self.recv_data()
                if data is None:
                    # Avoid tight loop when no data is received
                    time.sleep(0.1)
                    # Check if idle timeout is reached
                    if time.time() - last_active_time > IDLE_TIMEOUT:
                        logger.info("Idle timeout reached. Closing connection.")
                        self.conn.close()
                        break
                    continue
                else:
                    # Update last active time since we received data
                    last_active_time = time.time()
            except EOFError:
                logger.info("Connection reset by peer.")
                self.conn.close()
                break

            logger.debug("Received data of length: {}".format(len(data)))
            message = self.parse_data(data)

            # keep a record of all the previous states in order to handle some weird cases
            states.append(message.command)

            #Continue receiving binary
            if self.sending_binary:
                f = self.recv_binary_chunk(message, data, f)
                continue
            # look for the data header that is first sent when initiating a data connection
            #  /sdcard/stuff/exfiltrator-network-io.PNG,33206DATA
            elif bytes('DATA', "utf-8") in message.data[:128]:
                f = self.recv_binary(message, f)
                continue
            else:   # regular flow
                if len(states) >= 2 and states[-2:] == [protocol.CMD_WRTE, protocol.CMD_WRTE]:
                    logger.debug("Received Write/Write")
                    # last block of messages before the big block of data
                    try:
                        filename = str(message.data, "utf-8")
                    except UnicodeDecodeError as err:
                        filename = str(binascii.hexlify(message.data), "utf-8")
                    self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
                    # why do I have to send the command twice??? science damn it!
                    self.send_twice(protocol.CMD_WRTE, 2, message.arg0, 'STAT\x07\x00\x00\x00')
                elif states[-1] == protocol.CMD_WRTE and bytes('QUIT', "utf-8") in message.data:
                    logger.debug("Received quit command.")
                    #self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
                    self.send_message(protocol.CMD_CLSE, 2, message.arg0, '')
                elif len(states) > 2 and states[-2:] == [protocol.CMD_OKAY, protocol.CMD_WRTE]:
                    logger.debug("Received Okay/Write")
                    self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
                    # self.send_message(conn, protocol.CMD_WRTE, 2, message.arg0, 'FAIL', CONFIG)
                elif len(states) > 2 and states[-2:] == [protocol.CMD_WRTE, protocol.CMD_OKAY]:
                    logger.debug("Received Write/Okay")
                    self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
                    # self.send_message(conn, protocol.CMD_WRTE, 2, message.arg0, 'FAIL', CONFIG)
                elif len(states) > 1 and states[-2:] == [protocol.CMD_OPEN, protocol.CMD_WRTE]:
                    logger.debug("Received Open/Write")
                    self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
                    if len(message.data) > 8:
                        self.send_twice(protocol.CMD_WRTE, 2, message.arg0, 'STAT\x01\x00\x00\x00')
                        try:
                            filename = str(message.data, "utf-8")
                        except UnicodeDecodeError as err:
                            filename = str(binascii.hexlify(message.data), "utf-8")
                elif states[-1] == protocol.CMD_OPEN and bytes('shell', "utf-8") in message.data:
                    logger.debug("Received shell command.")
                    self.recv_shell_cmd(message)
                elif states[-1] == protocol.CMD_CNXN:
                    logger.debug("Received connection command.")
                    self.send_message(protocol.CMD_CNXN, 0x01000000, 4096, DEVICE_ID)
                elif states[-1] == protocol.CMD_OPEN and bytes('sync', "utf-8") not in message.data:
                    logger.debug("Received sync command.")
                    self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
                elif states[-1] == protocol.CMD_OPEN:
                    logger.debug("Received open command.")
                    self.send_message(protocol.CMD_OKAY, 2, message.arg0, '')
                elif states[-1] == protocol.CMD_CLSE and not self.sending_binary:
                    logger.debug("Received close command, 1.")
                    #self.send_message(protocol.CMD_CLSE, 2, message.arg0, '')
        duration = time.time() - start
        logger.info('{}\t{}\tconnection closed'.format(duration, self.addr[0]))
        obj = {
            'eventid': 'adbnectar.session.closed',
            'src_ip': self.addr[0],
            'duration': '{0:.2f}'.format(duration),
        }
        self.report(obj)
        self.conn.close()

class adbnectarPot:
    def __init__(self):
        self.bind_addr = CONFIG.get('honeypot', 'address')
        self.bind_port = int(CONFIG.get('honeypot', 'port'))
        self.download_dir = CONFIG.get('honeypot', 'download_dir')

    def accept_connections(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        """ Set TCP keepalive on an open socket.

            It activates after 1 second (after_idle_sec) of idleness,
            then sends a keepalive ping once every 1 seconds (interval_sec),
            and closes the connection after 100 failed ping (max_fails)
        """
        #self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # pylint: disable=no-member
        if hasattr(socket, 'TCP_KEEPIDLE'):
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
        elif hasattr(socket, 'TCP_KEEPALIVE'):
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, 1)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
        if hasattr(socket, 'TCP_KEEPCNT'):
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 100)
        # pylint: enable=no-member
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        self.sock.bind((self.bind_addr, self.bind_port))
        self.sock.listen(1)
        logger.info('Listening on {}:{}.'.format(self.bind_addr, self.bind_port))
        try:
            while True:
                conn, addr = self.sock.accept()
                logger.info("Received a connection, creating an ADBConnection.")
                thread = threading.Thread(target=ADBConnection, args=(conn, addr))
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            logger.info('Exiting...')
            self.sock.close()
            if output_writer:
                output_writer.stop()
            if downloader:
                downloader.stop()

def main():
    global logger
    global output_writer
    global downloader

    # Eventually these will be filled from a config file
    parser = ArgumentParser()

    parser.add_argument('-v', '--version', action='version', version="%(prog)s" + __version__)
    parser.add_argument('-a', '--addr', type=str, default="0.0.0.0", help='Address to bind to')
    parser.add_argument('-p', '--port', type=int, default=5555, help='Port to listen on (default: 5555)')
    parser.add_argument('-d', '--dlfolder', type=str, default="captured_samples", help='Directory for the uploaded samples (default: current)')
    parser.add_argument('-l', '--logfile', type=str, default="adbnectar.log", help='Log file (default: adbnectar.log')
    parser.add_argument('-j', '--jsonlog', type=str, default=None, help='JSON log file')
    parser.add_argument('-hn', '--hostname', type=str, default="Loki", help='Sensor/Host name')

    args = parser.parse_args()

    if args.addr:
        CONFIG.set('honeypot', 'address', args.addr)
    if args.port:
        CONFIG.set('honeypot', 'port', str(args.port))
    if args.dlfolder:
        CONFIG.set('honeypot', 'download_dir', str(args.dlfolder))
    if args.logfile:
        CONFIG.set('honeypot', 'log_file', args.logfile)
    if args.jsonlog:
        CONFIG.set('output_json', 'log_file', args.jsonlog)
    if args.sensor:
        CONFIG.set('honeypot', 'hostname', args.sensor)

    output_writer = OutputWriter()
    output_writer.start()

    if CONFIG.getboolean('honeypot','http_download', fallback=False):
        downloader = UrlDownloader()
        downloader.start()

    logger.info("Configuration loaded with {} as output plugins".format(OUTPUT_PLUGINS))

    honeypot = adbnectarPot()
    honeypot.accept_connections()

if __name__ == '__main__':
    main()
