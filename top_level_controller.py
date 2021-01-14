import socket
import struct
import threading
import time
import math
from uuid import getnode as get_mac

PORT = 5005
ADDRESS = "239.192.0.100"
ADDR = (ADDRESS, PORT)
MSS = 1300
MAC = get_mac()

LEN_MAC = 48
LEN_CODE = 3
LEN_MSG_BYTES = math.ceil((LEN_MAC + LEN_CODE) / 8)

PROBE = 0
ACTIVE = 1
STANDBY = 2
INEXISTANT = 3
HEARTBEAT = 4

HEARTBEAT_INTERVAL = 3
HEARTBEAT_TIMEOUT = 9
PROBE_REPEAT = 3

OTHER_TLC = ACTIVE
isActive = False

#######################################################################################################################################

#Definition of the multicast receiving socket
receive_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
receive_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
receive_socket.bind(('', PORT))
mreq = struct.pack("=4sl", socket.inet_aton(ADDRESS), socket.INADDR_ANY)
receive_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

#Definition of the multicast sending sokcet
send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

#######################################################################################################################################

def send(msg):
    """Sends a message to the TLC multicast address

    Parameters
    ----------
    msg : str 
        The message to be sent 
    """

    msg <<= LEN_MAC
    msg |= MAC
    msg = msg.to_bytes(LEN_MSG_BYTES, 'big')
    send_socket.sendto(msg, ADDR)


def decide_active(msg):
    """Election process, decides who is active based on greater MAC

    Parameters
    ----------
    msg : str
        The probing message that contains the MAC address
    """

    global isActive
    global OTHER_TLC
    converted = int.from_bytes(msg, "big")
    mask = (1 << LEN_MAC) -1
    other_mac = converted & mask
    if MAC > other_mac:
        isActive = True
        OTHER_TLC = STANDBY
    else:
        isActive = False
        OTHER_TLC = ACTIVE


def listen():
    """Listens and interprets messages according to the communication protocol
    """

    global OTHER_TLC
    global isActive
    while True:
        msg, addr = receive_socket.recvfrom(MSS)
        print(f"[{addr}] {msg}")
        if addr[0] != socket.gethostbyname(socket.gethostname()):
            converted = int.from_bytes(msg, "big")
            code = converted >> LEN_MAC

            if code == PROBE:
                OTHER_TLC = STANDBY
                if isActive:
                    send(ACTIVE)
                else:
                    send(STANDBY)
                    decide_active(msg)

            elif code == ACTIVE:
                OTHER_TLC = ACTIVE
                isActive = False

            elif code == STANDBY:
                OTHER_TLC = STANDBY
                decide_active(msg)
            
            elif code == HEARTBEAT:
                OTHER_TLC = ACTIVE
                isActive = False
                  

def probe():
    """Sends the probing message 
    """

    global isActive
    i = 0
    while(i < PROBE_REPEAT and OTHER_TLC == INEXISTANT and not isActive):
        i += 1
        send(PROBE)
        time.sleep(3)
    if OTHER_TLC == INEXISTANT:
        isActive = True


def send_heartbeat():
    """Sends hearbeat if isActive and sets other TLC to inexistent is notActive
    """

    global isActive
    global OTHER_TLC
    while True:
        if isActive and OTHER_TLC == STANDBY:
            send(HEARTBEAT)
            time.sleep(HEARTBEAT_INTERVAL)
        
        elif not isActive and OTHER_TLC == ACTIVE:
            OTHER_TLC = INEXISTANT
            time.sleep(HEARTBEAT_INTERVAL)
            if OTHER_TLC == INEXISTANT:
                isActive = True


#########################################################################################################################################

def start():
    print("[LISTENING] Starting to listen...")
    listen_thread = threading.Thread(target=listen, args=())
    listen_thread.start()
    probe()

    print(f"ACTIVE STATUS : {isActive}")
    print(f"OTHER TLC : {OTHER_TLC}")
    
    print("[HEARTBEAT] Starting Heartbeat thread...")
    heartbeat_thread = threading.Thread(target=send_heartbeat, args=())
    heartbeat_thread.start()

    while True:
        print(f"ACTIVE STATUS : {isActive}")
        print(f"OTHER TLC : {OTHER_TLC}")
        time.sleep(2)

start()


