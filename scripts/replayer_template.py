#!/usr/bin/env python
import readline
import socket
import glob
import sys
import os

# where we look for our initial first-run requests:
inp_dir = %s

# after we've loaded > 1 time, everything is saved to here:
work_dir = %s
# work_dir is overwritten if the --workdir param is given


# for printing purposes only 
ascii_threshold = .60
ascii_flag = True

request_dict = {}
saved_dict = {}

IP = ""
PORT = ""
TIMEOUT = 1
socket_mode = "kill"
sock = None
serv_sock = None

changes_flag = False

def main(): 

    cmd_dict = {
        "list":list_request,
        "save":save_request,
        "sendser":server_send_bytes,
        "send":client_send_bytes,
        "edit":edit_request,
        "send":client_send_bytes,
        "socket_mode":set_socket_mode,
        "rename":rename_request,
        "copy":copy_request,
        "reload":reload_request,
        "del":remove_request,
        "print":print_request, 
        "exit":cleanup,
        "quit":cleanup,
        "new_workdir":new_workdir,
        "load_dir":load_request_dir,
        "load":load_request,
        "print_mode":set_print_mode,
        "sethost":sethost,
        "pasteraw":paste_request,
        "pastehex":paste_hexstream,
        "pastecarray":paste_carray,
        "cmp":cmp_requests,
        "help":print_help,
        "?":print_help,
    }




    global work_dir
    sethost(sys.argv[1],sys.argv[2])
    
    try:
        ind = sys.argv.index("--workdir") 
        work_dir = sys.argv[ind+1]
    except:
        pass
    
    try:
        load_request_dir(work_dir)
    except:
        try:
            load_request_dir(inp_dir)
            new_workdir(work_dir)
        except:
            print "[x.x] Unable to load %s or %s"%(work_dir,inp_dir)
            sys.exit()
            
    if len(request_dict) == 0:
        print "[x.x] Unable to read in any requests from %s" % inp_dir
        sys.exit()


    tab_complete = TabCompleter(cmd_dict,request_dict)
    print "[^_^] Loaded %d requests"%len(request_dict)

    while True:
        try:
            inp = filter(None,raw_input("%s[^.^]> %s"%(PURPLE,CLEAR)).split(" "))
        except:
            print ""
            continue 

        if not len(inp):
            continue
        try:
            cmd = inp[0]
            args = inp[1:]
            cmd_dict[cmd](*args)
        except KeyError as e:
            print e
        
            try:
                os.system(" ".join(inp))
            except Exception as e:
                print e
                print "[x.x] Invalid command: %s" % inp
        except KeyboardInterrupt:
            continue
        except TypeError as e:
            print "[?.?] Wrong num of params for command %s"%cmd
            print e
        except Exception as e:
            print e
    

def sethost(ip,port=""):
    global IP
    global PORT
    
    # if someone does "ip:port", w/e.
    if not port:
        try:
            ip,port = ip.split(":")
        except:
            print "[;_;] Bad ip/port"

    try:
        IP = ip
        if len(IP.split(".")) != 4:
            print "[>.>] Invalid IP given"
            return
        PORT = int(port)
    except:
        print "[x.x] Invalid params given to sethost!"
        return
       
  
def set_print_mode(mode):
    global ascii_flag

    if mode == "ascii":
        ascii_flag = True
    elif mode == "binary":
        ascii_flag = False

def list_request():
    print "[!.!] Current Request Listing~" 
    req_list = request_dict.keys()
    req_list.sort()
    for req in req_list:
        print_request(req,truncate=True)


# connect to server and then send commands.
def client_send_bytes(*request_ids):
    send_bytes("client",*request_ids)    

# wait for client to connect before sending bytes.
def server_send_bytes(*request_ids):
    send_bytes("server",*request_ids)    

def set_socket_mode(mode):
    global socket_mode
    if mode == "persist":
        socket_mode = "persist"
    elif mode == "kill":
        socket_mode = "kill"
    else:
        print "invalid set_socket_mode args: %s" % (mode,)

def send_bytes(mode,*request_ids):
    global sock
    global serv_sock

    if socket_mode != "persist" or sock == None:
        if mode == "client": 
            try:
                sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
                sock.connect((IP,PORT))
                sock.settimeout(TIMEOUT)
            except:
                print "[x.x] Unable to connect to %s:%d"%(IP,PORT)
                print "Consider using 'sethost' cmd to fix." 
                return

        elif mode == "server":
            try:
                sock,cli_addr = serv_sock.accept()
            except:
                serv_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
                serv_sock.bind((IP,PORT))
                print "Bound to %s:%d"%(IP,PORT)
                serv_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                serv_sock.listen(1)
                sock,cli_addr = serv_sock.accept()

            print "[1.1] Connection bekommt: (%s:%d)"%(cli_addr)
            sock.settimeout(TIMEOUT)
            # we recv first if server sock. Might need cmdline flag later
            # if/when we run into a server socket that needs to send first.
            get_bytes(sock)
        else:
            print "[?.?] Invalid send_bytes mode: %s" % mode
            return


    for request_id in request_ids:
        req = request_dict[request_id]
        print CYAN + "[>.>] Sending %s %d bytes~"%(request_id,len(req))
        try:
            sock.send(req)
            ret = get_bytes(sock)

            if ret:
                print YELLOW + "[<.<] Got %d bytes~" % len(ret)
                if len(ret) > 0x1000: 
                    ret = ret[0:0x1000]

                buf = "" 
                for char in ret:
                    if ord(char) >= 0x30 and ord(char) <= 122 and ascii_flag:
                        buf+=char
                    else:
                        buf+="\\x%02x"%ord(char)
                print buf
            else:
                print "[x.x] No response..."

        except Exception as e:
            if "Broken pipe" in e:
                sock = None
                break
            else:
                print e

        #print "[!-!] Saving response as %s_resp"%(request_id)
        #save_request("%s_resp"%request_id,buf)

    sock = None
    
    '''
    if socket_mode != "persist":
        sock.close()
        if mode == "server":
            serv_sock.close()
    '''
   
         
    
def get_bytes(sock):
    tmp = ""
    ret = ""
    while True:
        try:
            tmp = sock.recv(65535)        
            if tmp:
                ret+=tmp
            else:
                break
        except:
            break

    return ret


def edit_request(request_id,start_index,new_val):
    pass
   

def copy_request(old_request_id,new_request_id):
    rename_request(old_request_id,new_request_id,copyOnly=True)

def rename_request(old_request_id,new_request_id,copyOnly=False):
    global changes_flag
    try:
        val = request_dict[old_request_id]
        del request_dict[old_request_id]
        filename = os.path.join(work_dir,old_request_id)
        if not copyOnly:
            os.remove(filename)
        changes_flag = True
    except Exception as e:
        print "Could not remove old request %s (%s)"%(old_request_id,e)
        return

    save_request(new_request_id,val)


# Will generate a new request file with name <request_id> 
# in the work_dir that contains the request in <request_value>
def save_request(request_id,request_value):
    global request_dict
    global changes_flag

    filtered_request = ""
    escape_loc = request_value.find("\\x")
    # all chars should be escaped if not ascii, so no slashes shuold be in buf. 
    while escape_loc > -1:
        filtered_request += request_value[:escape_loc] 
        filtered_request += chr(int(request_value[escape_loc+2:escape_loc+4],16))
        request_value = request_value[escape_loc+4:]
        escape_loc = request_value.find("\\x")
    filtered_request+=request_value
        
    try:
        request_dict[request_id] = filtered_request
    except Exception as e:
        print "[x.x] Could not add request %s to request_dict, returning."%request_id
        return

    req_path = os.path.join(work_dir,request_id)

    try:
        with open(req_path,"wb") as f:
            f.write(request_value)
        changes_flag = True
    except Exception as e:
        print "[x.x] Could not create %s in work_dir"%request_id
        print e
        return 


# Print out the given <request_id>
def print_request(request_id,truncate=False):
    try:
        req = request_dict[request_id]
    except KeyError:
        print "[x.x] Request %s not found in request_dict"%request_id
        return
    
    if truncate and len(req) > 50:
        old_len = len(req)
        req = req[0:50]
        
    buf = ""
    for char in req:
        if ord(char) >= 0x30 and ord(char) <= 122 and ascii_flag:
            buf+=char
        else:
            buf+="\\x%02x"%ord(char)
    print "-------------------"
    if len(req) == 50:
        buf+="%s[...] (50/%d bytes)%s" % (YELLOW,old_len,CLEAR)
    print "%s%s (%d bytes (0x%lx))\n%s%s" % (CYAN,request_id,len(req),len(req),CLEAR,buf)          


def cleanup(): 
    if changes_flag:
        print "[?.?] Would you like to save request changes to the current workdir? (y/n)"
        if raw_input(":").lower() == "y":
            new_workdir(work_dir,force=True)
    sys.exit()
             

def new_workdir(directory,force=False):
    try:
        os.mkdir(directory)
    except:
        if not force:
            print "[?.?] Dst dir already exists, would you like to overwrite? (y/n)" 
            if raw_input(":").lower() != "y":
                print "[-.-] Declining to write then, returning"
                return

    for req in request_dict:
        try:
            req_name = os.path.join(directory,req)
            with open(req_name,"wb") as f:
                f.write(request_dict[req]) 
        except Exception as e:
            print "[;_;] Unable to save request %s to %s (%e)"%(req,directory,e)
            if not force:
                return

def reload_request():
    load_request_dir(work_dir)

def load_request_dir(directory):
    for f in os.listdir(directory):
        load_request(os.path.join(directory,f)) 

def load_request(request_file):
    global request_dict
    try:
        request_name = os.path.basename(request_file)
        with open(request_file,"rb") as f:
            request_dict[request_name] = f.read()
    except Exception as e:
        print "[x.x] Unable to load request %s (%s)" % (request_name,e)

def remove_request(request_name):
    try:
        del request_dict[request_name]
        print "[!.!] %s removed from request_dict" % request_name
    except Exception as e:
        print "[?.?] Unable to remove %s: %s"%(request_name,e)
        pass

    try:
        os.remove(os.path.join(work_dir,request_name))
    except:
        pass

def cmp_requests(req1,req2):
    try:
        r1 = request_dict[req1] 
        r2 = request_dict[req2] 
    except Exception as e:
        print "[?.?] Could not find one or more reqs: %s, %s"%(req1,req2)
        print e
        return    

    if len(r1) > len(r2):
        longer = r1     
        shorter = r2
    else:
        longer = r2
        shorter = r1 
    print "%sLen(%s): %d, Len(%s): %d%s"%(GREEN,req1,len(r1),req2,len(r2),CLEAR) 
        
    buf = ""
    i = 0
    j = 0
    y = 0
    orig_diff = 0
    while i < len(shorter):    
        for x in range(len(shorter),i+4,-1): 
            #print "start i(%d),j(%d),y(%d),x(%d)"%(i,j,y,x)
            match = longer[j:].find(shorter[i:x])
            if match == 0:
                #print YELLOW + "Found match " + CLEAR + "ind(%d) %s\nin\n%s"%(match,repr(shorter[i:x]),repr(longer[j:]))

                buf += GREEN
                for y in range(i,x):
                    if ord(shorter[y]) >= 0x30 and ord(shorter[y]) <= 122:
                        buf+=shorter[y]
                    else:
                        buf+="\\x%02x"%ord(shorter[y])
                j+=(x-i)
                i+=(x-i)
                break

        if i >= len(shorter) or j > len(shorter):
            break  
                
        
        # no min 4 byte match
        buf+=YELLOW
        #print "break i(%d),j(%d),y(%d),x(%d)"%(i,j,y,x)
        #print "stop match ind(%d) %s\nin\n%s"%(match,repr(shorter[i:]),repr(longer[j:]))
        for q in range(0,match+1):
            if ord(longer[j+q]) >= 0x30 and ord(longer[j+q]) <= 122:
                buf+=longer[j+q]
            else:
                buf+="\\x%02x"%ord(longer[j+q])
            j+=match
            j+=1

        i+=1
        if j >= len(shorter):
            #print "i(%d),j(%d),lenshort(%d)"%(i,j,len(shorter))
            break
    
    buf += CYAN
    s = len(shorter)
    for i in range(s,len(longer)):
        if ord(longer[i]) >= 0x30 and ord(longer[i]) <= 122:
            buf+=longer[i]
        else:
            buf+="\\x%02x"%ord(longer[i])
    buf += CLEAR
    
    print "[^_^] Request Diff: (Key:%sMATCH,%sDIFF,%sAPPEND)\n%s%s" % (GREEN,YELLOW,CYAN,buf,CLEAR)


def process_carray(req_buf):
    buf = ""
    left_bracket = req_buf.find("*/")+2
    right_bracket = req_buf.rfind("}")
    if left_bracket == -1 or right_bracket == -1:
        print "[x.x] Bracket missing for paste_carray..."
        return ""
    
    byte_buf = req_buf[left_bracket:right_bracket].replace("\n","").replace(" ","") 
    
    print repr(byte_buf)
    print byte_buf.split(",")
    for b in byte_buf.split(","):
        try:
            i = int(b,16)
            if i > 0x30 and i < 122: 
                buf+=chr(i)
            else:
                buf+= "\\x%02x"%i
        except:
            pass

    return buf
    

def process_hexstream(buf):
    req_buf = ""
    for i in range(0,len(buf),2):
        tmp = chr(int(buf[i:i+2],16))
        if ord(tmp) > 0x30 and ord(tmp) < 122: 
            req_buf += tmp
        else:
            req_buf += "\\x%02x"%ord(tmp)

    return req_buf

def paste_process(request_name,format_function):
    print "Newlines will be ignored, use \\x0a for newlines in bytestream" 
    print "Comment lines with '#'. Ctrl-C to finish input (and remember to hit <ENTER> first)"

    buf = ""
    while True: 
        try:
            tmp = raw_input("")
            tmp = tmp.rstrip().lstrip()
            if tmp.startswith("#"):
                continue
            if len(tmp):
                buf+=tmp
        except KeyboardInterrupt:
            break
    
    if format_function != None:
        buf = format_function(buf)

    if len(buf):
        save_request(request_name,buf)
    else:
        print "[1.1] No-go on saving of %s" % request_name

def paste_carray(request_name):
    print "[!.!] Being pasting carray request"
    paste_process(request_name,process_carray)

def paste_hexstream(request_name):
    print "[!.!] Being pasting hexstream request"
    paste_process(request_name,process_hexstream)

def paste_request(request_name):
    print "[!.!] Being pasting request"
    paste_process(request_name,None)


def usage():
    print "[?.?] Usage: %s <ip> <port>" 
    sys.exit()

def print_help():
    ret = '''\
    <(^_^)> Decept Autogen'ed API replayer thing:
    "list":list_request()                         - Prints out all available API requests.
    "send_server":server_send_bytes(*request_ids) - Sends the requests to a server (connecting as client)
    "send_client":client_send_bytes(*request_ids) - Sends a requests to a client (after waiting for the connect/first packet.)
    "socket_mode":set_socket_mode(mode)           - Toggle killing of sockets after sending all reqs.
                                                    Available: {"persist","kill"} (default => kill) 
    "save":save_request(request_id,request)       - Adds request to the request_dict 
                                                    and also writes a file to the workdir.
    "rename":rename_request(old,new)              - Moves request in request_dict and filesystem. 
    "del":remove_request(request)                 - Removes request.
    "print":print_request(request_id)             - Prints the given request for <request_id>
    "exit":cleanup()                              - Obv.
    "new_workdir":new_workdir(directory)          - Writes all request entries to <directory> and 
                                                    switches work_dir to <directory>
    "load_dir":load_request_dir(directory)        - Loads all requests from <directory> into the
                                                    current request_dict.
    "load":load_request(file)                     - Loads a single request into the request_dict
    "print_mode":set_print_mode(mode)             - Controls how the print/list commands operate.
                                                    Available modes: {"binary","ascii"} (default => ascii) 
    "sethost":sethost(ip,port)                    - Change remote endpoint to <ip>:<port>
    "pasteraw":paste_request(request_name)        - Enter mode to input raw bytes till CTRL+C 
                                                    and save as <request_name>

    "pastehex":paste_hexstream(request_name)      - Enter mode to input a hexstream till CTRL+C.
                                                    (e.g. "3abc12ef10") 
    "cmp":cmp_requests(r1,r2)                     - Prints out color diff of requests r1,r2

    '''

    print ret
       
#colors
RED='\033[31m'
ORANGE='\033[91m'
GREEN='\033[92m'
LIME='\033[99m'
YELLOW='\033[93m'
BLUE='\033[94m'
PURPLE='\033[95m'
CYAN='\033[96m'
CLEAR='\033[00m' 

class TabCompleter(object):

    def __init__(self,options,requests):
        self.cmdoptions = sorted(options) 
        self.requests = sorted(requests)
        self.matches = []
        self.text = ""

        readline.parse_and_bind('tab: complete')
        readline.parse_and_bind('set editing-mode vi')
        readline.set_completer(self.tabcomplete)
    
    def tabcomplete(self,text,index):
        answer = ""
        if text != self.text or not text:
            self.matches = []
            self.text = text

            if not readline.get_begidx():
                for o in self.cmdoptions:
                    if o.startswith(text):
                        self.matches.append(o)
            else:
                cmd_text = filter(None,readline.get_line_buffer().split(" "))
                if len(cmd_text) == 1:
                    self.matches = self.requests[:] 
                else:
                    self.matches = [s for s in self.requests if s.startswith(cmd_text[-1])]
                

            if len(self.matches) == 1:
                ret = self.matches[0]
            elif len(self.matches) > 1:
                self.text = str(self.matches)
            elif len(self.matches) == 0:
                self.text = str(self.matches)
            
        else:
            try:
                ret = self.matches[state]
            except IndexError:
                pass
    
        try:
            ret = self.matches[index]
        except:
            pass

        '''
        if len(ret):
            sys.__stdout__.write("\n")
        sys.__stdout__.write("%s[^.^]> %s%s" % (PURPLE,CLEAR,ret))
        sys.__stdout__.flush()
        '''
        return ret
                         

if __name__ == "__main__":

    print CYAN +  "<(^_^)> Decept Autogen'ed API replayer thing:" + CLEAR
    if len(sys.argv) < 3:
        usage() 
    main()
