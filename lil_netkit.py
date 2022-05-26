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



from time import sleep
DEBUG=False
#DEBUG=True

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
rainbow = [RED,ORANGE,YELLOW,GREEN,BLUE,PURPLE]

# Have to use shortest possible versions
# for the commands we care about
crypto_key_gen_rsa = ["cry","key","g","r"]

## filter list tuple format:
## ([string|list|empty],[action_method(params,...),action_method(params,..)])
# "" => always execute action_method
# ("", [replace("exportable","non-exportable)])
# Empty rules always execute first

class lil_netkit():
    def __init__(self,mode="default"):
        
        self.color = 0
        self.rainbow_on = False
        self.client_buffer = None
        self.mode = mode

        self.on_connect_hook = [ 
        # not implimented
        ]
        
        self.on_disconnect_hook = [
        # not implimented
        ]
        
        self.out_filter_list = [
            #(crypto_key_gen_rsa, [insert_word_at_index(4,"exportable")]),
        ] 

        # in_filter isn't exactly working due to the processing that needed
        # to be done in order to get the more important out_filter working
        self.in_filter_list = [
            (["Password:"],[self.disable_echo]),
        ] 


    #TODO: be able ot import filters 
    def input_filters(self,filename):
        pass
        
    def init_client_buffer(self,client_channel,server_channel):
        # append cisco commands if needed
        if self.mode == "cisco":
            self.client_buffer = CiscoSSHClientBuffer(client_channel,server_channel)
            self.out_filter_list.extend(self.client_buffer.out_filters)
            self.in_filter_list.extend(self.client_buffer.in_filters)
        else:
            self.client_buffer = SSHClientBuffer(client_channel,server_channel)

    def disable_echo(self):
        print("DISABLEING ECHO")
        self.client_buffer.disable_echo()

    def enable_echo(self):
        self.client_buffer.echo_flag = True

    def directional_filter(self,filter_list,message):
        if not len(message):
            return message 

        tmp_split = filter(None,message.split(" "))
        ret = ""

        for filter_rule in filter_list:
            if not tmp_split:
                return message

            if DEBUG:
                print("FILTER_RULE: %s" % str(filter_rule))
            good = False

            # case: "" => always execute
            if not filter_rule[0]:  
                for action in filter_rule[1]:
                    try:
                        if DEBUG:
                            print(action)
                        ret = action(message)
                        if not ret:
                            if DEBUG:
                                print("Couldn't apply action:%s" %(str(action)))
                    except Exception as e:
                        try:
                            action()
                        except:
                            pass
                        if DEBUG:
                            print(str(e))
                continue
      
            # case: [1,2,3] => only execute if parser match 
            for i in range(0,len(tmp_split)):     
                
                if DEBUG: 
                    #print "TMPSPLIT == %s" % repr(tmp_split)
                    print(type(tmp_split))
                    print("TMP[%d]:%s ~= %s??" % (i,tmp_split[i],filter_rule[0][i]))
                    print(filter_rule[0])
            
                if tmp_split[i].find(filter_rule[0][i]) != 0:
                    # no match, try next filter_rule
                    break 

                if i+1 == len(filter_rule[0]): 
                    good = True
                    break
           
            if not good:
                if DEBUG:
                    print ("no good")
                continue

            for action in filter_rule[1]: 
                if DEBUG:
                    print("APPLYING ACTION:%s" % str(action))
                try:
                    ret = action(message)
                    if not ret:
                        if DEBUG:
                            print("Couldn't apply action:%s" %(str(action)))
                        continue
                    
                except Exception as e:
                    ret = action()

        if ret:
            if DEBUG:
                print(ret)
            return ret
        else:
            return message
                
             
    def inbound_filter(self,message):
            print(GREEN)
            print("INbound filter on message: %s" % message)
            print(CLEAR)
            return self.directional_filter(self.in_filter_list,message)

    def outbound_filter(self,message):
            ret = self.client_buffer.take_input_action(message)
            if ret:
                print(GREEN)
                print("Outbound filter on message: %s" % ret)
                print(CLEAR)
                return self.directional_filter(self.out_filter_list,ret)
            return []
             

##### Action Methods
def get_space_loc(index,string):
    tmp = filter(None,string.split(" "))
    ret = 0
    for i in range(0,index):
        ret+=len(tmp[i]) 
        ret+=1 #for spaces
    return ret
    
    
def insert_word_at_index(index,word):
    # oh my god, what have I done.
    return lambda x: "%s %s %s" % (x[0:get_space_loc(index,x)],
                                   word,
                                   x[get_space_loc(index,x):]) 
def append(addition):
    return lambda message: "%s %s" % (message,addition) 

def remove(badword):
    return lambda message: message.replace(badword,"") 

def inc_num(num):
    return lambda color: color + num

# Since there's some minor processing of a user's SSH client
# on the input that they do, that's not normally seen,
# this class is to do all that under-the-hood stuff so that
# lil_sshniffer doesn't really have to care about it.
#
# SSHClientBuffer(in_chan,out_chan)
##  in_chan  : ssh channel client is connected to.
##  out_chan : ssh channel the target server is connected with.
## (paramiko ssh channels)
##  mode : enable controls of certain chars based on device type
### Currently Supported:
#
class SSHClientBuffer(object):

    def __init__(self,in_chan,out_chan):
        self.debug = True
        self.client = in_chan
        self.server = out_chan
        
        self.echo_flag = True

        self.client_buffer = [] 
        self.cursor_index = 0
        self.previous_byte = "" #sometimes > 1 byte (e.g. arrows)
        self.echo_expected = False

        # --More-- => q," ",Enter,Ctrl-c
        self.more_switch = False

        self.arrow_flag = False

        self.backspace_chars = "\x08 \x08"
        self.action_dict = {
            "\x7f":self.backspace,
            "\r":self.newline,
            "\t":self.tab_complete,
            #
            "\x1b[A":self.up_arrow, 
            "\x1b[B":self.down_arrow, 
            "\x1b[C":self.right_arrow,
            "\x1b[D":self.left_arrow,
            # 
            "\x01":self.ctrl_a,
            "\x05":self.ctrl_e,  
            "\x03":self.ctrl_c,
            #"\x18":self.ctrl_x,
            #"\x1a":self.ctrl_z,
            #
        }

        # for getting server response
        self.timeout = .01


    def display_client_buffer(self,force=False):
        buf = ""
        #print "CLIENT SENDING:%s" %repr(self.client_buffer)
        self.client.send(''.join(self.client_buffer))
        # for situations (tab) where we don't 
        # want to ignore the command we just sent
        if force==True:
            self.client.send(buf)
        
    def clear_client_buffer_display(self,till_cursor=True):    
        count = 0
        for byte in ''.join(self.client_buffer[0:self.cursor_index]):
            if ord(byte) >= 0x20 and ord(byte) < 0x7f:
                count+=1

        if till_cursor:
            self.client.send(self.backspace_chars * (count-self.cursor_index)) 
        else:
            self.client.send(self.backspace_chars*(count))

    def disable_echo(self):
        self.echo_flag = False

    def enable_echo(self):
        self.echo_flag = True

    def debug_output(self,string):
        if self.debug:
            print("[?.?] Debug: %s" % string) 

    # for when \t or arrows are in play
    # and we expect an immediate response
    def get_server_response(self,timeout=1,increase_timeout=True):
        old_timeout = self.server.gettimeout() 
        self.server.settimeout(timeout)
        
        ret = ""
        try:
            ret = self.server.recv(4096) 
        except:
            try:
                ret = self.server.recv(4096) 
                sleep(self.timeout) 
            except Exception as e:
                if increase_timeout:
                    self.timeout+=.01
                    self.debug_output("TIMEOUT NOW %f" %self.timeout)
                    # is our timeout too fast???
            
        if old_timeout:
            self.server.settimeout(old_timeout) 
        # if there's control bytes, ignore
        
        return ret

    # for when we're parsing responses to --More--
    def get_client_input(self,timeout=0):
        old_timeout=0
        if timeout:
            old_timeout = self.server.gettimeout() 
            self.client.settimeout(timeout)
        
        ret = ""
        while True:
            try:
                ret = self.client.recv(4096) 
                break
            except:
                pass
            
        if old_timeout:
            self.client.settimeout(old_timeout) 

        return ret




    # Given bytes, will dicern what to do based off
    # of the action_dict. If there is any output that
    # we need to send explicitly to the client, such
    # as the response to a command, it will be returned
    # as a list. 
    #
    def take_input_action(self,byte):
        #store if needed
        self.debug_output("BYTE: %s" % repr(byte))
        ret = []
        double_up_switch = False

        if len(byte) > 1:
            try:
                ret = self.action_dict[byte]()        
                self.debug_output("SENDING: %s" % repr(ret))
                self.previous_byte = byte
                return ret
            except KeyError:
                pass

        for b in byte:
            try:
                ret.append(self.action_dict[byte]()) 
                double_up_switch = True
            except KeyError:
                pass

            if not double_up_switch and ord(b) >= 0x20 and ord(b) < 0x7f:
                ret.append(self.normal_ascii_action(b))

            self.previous_byte = byte
        
        #print "Action Ret: %s" % str(ret)
        if len(ret) > 1:
            buf = ""
            for i in ret:
                if i:
                    buf += i
            return buf
        elif len(ret) == 1:
            return ret[0] 
             
    def send_server_immediate(self,byte):
        self.server.send(byte) 
        self.debug_output("SEND_IMMED: %s" % repr(byte))

    # removes last $amt printable bytes from client_buffer
    # starting at cursor_index  
    def clear_client_buff_char(self,amt=1):
        self.debug_output("BEFORE CLEAR:%s"%repr(self.client_buffer))
        self.debug_output("CURSOR_INDEX:%d"%self.cursor_index)

        if len(self.client_buffer) == 1:
            self.cursor_index = 0
            self.update_client_buffer([],display=True)
            return

        try:
            self.update_client_buffer(self.client_buffer[0:self.cursor_index-amt] + \
                                      self.client_buffer[self.cursor_index:]) 
        except IndexError:
            self.update_client_buffer(self.client_buffer[self.cursor_index:])
        self.debug_output("AFTER CLEAR:%s"%repr(self.client_buffer))

        if self.cursor_index > 0: 
            self.cursor_index -=1
          

    def ascii_filter(self,byte):
        if byte == "\\x1b":
            return False 
        if ord(byte) >= 0x20 and ord(byte) < 0x7f: 
            return True 
        return False

    def update_client_buffer(self,new_buffer,display=False):
        self.debug_output("Before Update: %s" % repr(self.client_buffer))
        #self.clear_client_buffer_display()

        self.client_buffer = filter(self.ascii_filter,new_buffer)
        self.debug_output("After Update: %s" % repr(self.client_buffer))
        
        if display:    
            self.display_client_buffer()
        

    def passthrough(self,byte):
        #print "PASSTHFOUGH: %s" % repr(byte)
        self.server.send(byte)
        self.client.send(byte)
#################################
# Begin implimentation of key actions
#################################

    def newline(self): 

        if len(self.client_buffer) and not self.arrow_flag: 
            tmp = ''.join(self.client_buffer[:]) + "\r"
            self.client_buffer = []
            self.cursor_index = 0
            return tmp
        elif len(self.client_buffer) and self.arrow_flag:
            self.arrow_flag = False
            ret = self.get_server_response(self.timeout,increase_timeout=False)         
            #print "ret: %s" % repr(ret)
            self.server.send("\x03")
            ret = self.get_server_response(self.timeout,increase_timeout=False)         
            #print "ret: %s" % repr(ret)
            tmp = ''.join(self.client_buffer[:]) + "\r"
            self.client_buffer = []
            self.cursor_index = 0
            return tmp
        else:
            self.passthrough("\r")
            self.arrow_flag = False

    def tab_complete(self,tab="\t"): 
        self.send_server_immediate(''.join(self.client_buffer) + tab)

        if self.previous_byte == tab:
            self.send_server_immediate(tab)
        else:
            self.previous_byte = tab

        buff = ""
        resp = " "
        # discard/deal with null responses and server echo
        while len(resp):
            resp = self.get_server_response(self.timeout,increase_timeout=False)         
            if not len(resp):
                break
            buff += resp 

        tmp = ''.join(self.client_buffer)

        # Case 1: No completion was found
        if buff == tmp + "\x07" or buff == tmp + "\x07\x07": 
            #print "path2"
            self.server.send("\x03") # ctrl_c to clear out the server's buffer
            # ignore the ctrl_c response
            ret = " "
            while len(ret):
                ret = self.get_server_response(self.timeout,increase_timeout=False)         
            self.client.send("\x08" * (len(filter(self.ascii_filter,self.client_buffer))))
            self.client.send("\x07")
            self.client.send(tmp)
            return
            
        # Case 2: >1 completion was found
        elif buff.find(tmp + "\x07") == 0:
            #print "path3"
            # need to strip out extraineious output buffers
            # - Everything before "\x07"
            #resp = self.get_server_response(self.timeout,increase_timeout=False)         

            buff_split = buff.split("\r\n")
            if len(buff_split) == 1:
                appended = buff[buff.find("\x07")+1:].replace("\x07","")
                self.client_buffer+=list(appended)
                self.previous_byte = appended[-1]
                self.cursor_index = len(self.client_buffer)
                self.send_server_immediate("\x7f" * len(self.client_buffer)) 
                self.display_client_buffer()
                return

            # we send spaces too in order to account for the desync between
            # the client's buffer and the server's buffer 

            last_line = buff_split[-1] 
            message_body = buff[buff.find('\x07'):buff.find(last_line)]
            self.client.send(message_body)
            #! filtering for newline/etc
            if "--More--" in buff:
                #print "Found More"
                self.client.send("--More--")
                tmp = self.more_handler()
                if tmp:
                    self.client.send(tmp)
    
                last_line = ""
            else:
                last_line = buff_split[-1] 

            if len(last_line):
                self.client.send(last_line)
            self.client.send(" " * len(self.client_buffer))
            self.send_server_immediate("\x7f" * len(self.client_buffer)) 
        else:
            # case 3: Valid Completion was found
            #print "path1"
            try:
                self.previous_byte = self.client_buffer[-1]
            except:
                pass
            self.cursor_index = len(self.client_buffer)

            # to clear out both buffers
            self.server.send("\x03") 
            ret = " "
            while len(ret):
                ret = self.get_server_response(self.timeout,increase_timeout=False)         

            # clear old buffer
            self.client.send("\x08" * (len(filter(self.ascii_filter,self.client_buffer))))
            self.client.send("\x07")
        
            # then display new buffer
            self.client_buffer = list(buff)
            self.cursor_index = len(self.client_buffer)
            self.client.send(''.join(self.client_buffer))
    
    def normal_ascii_action(self,byte,send=True):
        if self.more_switch:
            self.send_server_immediate(byte)
            tmp = self.get_server_response(self.timeout)
            return

        if self.cursor_index != len(self.client_buffer):    
            self.clear_client_buffer_display(till_cursor=True)
            self.client_buffer.insert(self.cursor_index,byte)
            self.debug_output("CURSOR_INDEX:%d"%self.cursor_index)

            if self.echo_flag == True:
                self.client.send(self.after_cursor_index())
                self.client.send("\x1b[D" * (len(self.after_cursor_index())-1))
                self.cursor_index += 1

        else:
            self.client_buffer.append(byte) 
            if self.echo_flag == True:
                self.client.send(byte) 
            self.cursor_index+=1
    
    def after_cursor_index(self):
        tmp = ''.join(self.client_buffer[self.cursor_index:])
        self.debug_output("AFter cursor index: %s" % repr(tmp))
        return tmp


    def backspace(self):

        if len(self.client_buffer) and self.cursor_index > 0:
            # backspace chars
            self.cursor_index-=1
            try:
                self.client_buffer = filter(self.ascii_filter,self.client_buffer[:self.cursor_index] + list(self.client_buffer[self.cursor_index+1:])) 
            except IndexError:
                self.client_buffer = self.client_buffer[:self.cursor_index]

            if self.echo_flag == False:
                return

            # clear any extraneous
            self.client.send("\x08\x1b[K")
            #complete rest of client's output
            self.client.send(''.join(self.client_buffer[self.cursor_index:])) 
            # move cursor back into position
            self.client.send("\x08" * (len(self.after_cursor_index())))

        self.debug_output("clibuff affter back:%s"%str(self.client_buffer))

    def up_arrow(self):
        self.send_server_immediate("\x1b[A")
        tmp = self.get_server_response(self.timeout,increase_timeout=False)
        if len(tmp):
            backspace = self.get_server_response(self.timeout,increase_timeout=False)
            self.client.send(backspace) 
            self.client.send(tmp)
            self.update_client_buffer(list(tmp.replace("\x1b[K","")))
            self.cursor_index = self.get_printable_length(tmp)
        
            self.arrow_flag = True

    def down_arrow(self):
        self.send_server_immediate("\x1b[B")
        tmp = self.get_server_response(self.timeout,increase_timeout=False)
        if len(tmp):
            self.server.send("\x1b[K")
            backspace = self.get_server_response(self.timeout,increase_timeout=False).replace("\x1b[K","")
            self.client.send(backspace) 
            self.client.send(tmp)
            self.update_client_buffer(list(tmp.replace("\x1b[K","")))
            self.cursor_index = self.get_printable_length(tmp)
        
            self.arrow_flag = True

    def right_arrow(self):
        if self.cursor_index < len(self.client_buffer):
            self.cursor_index += 1 
            self.client.send("\x1b[C")

    def left_arrow(self):
        if self.cursor_index > 0:
            self.cursor_index -= 1    
            self.client.send("\x1b[D")
            self.debug_output("Cursor index after: %d" % self.cursor_index)
 
    def ctrl_a(self):
        self.cursor_index = 0
        self.client.send("\x01")
        self.client.send("\x08" * len(self.client_buffer))
    
    def ctrl_e(self):
        self.client.send("\x05")
        self.client.send("\x1b[C"*len(self.after_cursor_index()))
        self.cursor_index = len(self.client_buffer)

    def ctrl_c(self):
        self.passthrough("\x03")
        self.clear_client_buffer_display()
        self.client_buffer = []
        self.cursor_index = 0
        self.echo_flag = True

#################################
# End implimentation of key actions    
#################################
    def get_printable_length(self,buff):
        ret_int = 0

        for byte in ''.join(buff):
            if ord(byte) >= 0x20 and ord(byte) < 0x7f:
                ret_int+=1

        return ret_int
         
    def more_handler(self):

        tmp = self.get_client_input()
        self.send_server_immediate(tmp) 

        resp = self.get_server_response(self.timeout,increase_timeout=False)         
    
        self.client.send(resp)
        if "--More--" in resp:    
            self.more_handler()


# Needed for Cisco router/etc specifc SSH handling
class CiscoSSHClientBuffer(SSHClientBuffer):
    
    def __init__(self,input_channel,output_channel):
        super(CiscoSSHClientBuffer,self).__init__(input_channel,output_channel)
        self.action_dict['?'] = self.question_complete
        self.enable = False
        self.hijack_flag = False
    
        self.out_filters = [
            (["en"],[self.disable_echo,self.set_enable_mode]),            
            (["exit"],[self.set_hijack_flag]),     
            (["quit"],[self.disable_or_quit]),
        ]

        self.in_filters = [
            ([" --More-- "],[self.more_filter]),
            (["--More--"],[self.more_filter]),
        ]

    def more_filter(self):
        tmp = self.more_handler()
        if tmp:
            self.client.send(tmp)

    def more_handler(self):
        #print "ENTERING MORE HANDLER"
        tmp = self.get_client_input()
        self.send_server_immediate(tmp) 

        resp = self.get_server_response(self.timeout,increase_timeout=False)         
        self.client.send(resp)
        #print repr(resp)

        if "--More--" in resp:    
            self.more_handler()

    def question_complete(self):
        if len(self.client_buffer):
             self.send_server_immediate(''.join(self.client_buffer))
        self.send_server_immediate("?")
        # Discard, should be echo of what we sent
        resp = ""
        tmp = " "
        while len(tmp):
            tmp = self.get_server_response(self.timeout,increase_timeout=False)         
            resp+=tmp
            if DEBUG:
                print("RESPONSE TO ?: %s" % repr(resp))
        

        tmp = resp.find("\r\n")
        if DEBUG:
            print("sendint to cli:%s" % repr(resp[tmp:]))
        self.client.send(resp[tmp:]) # ignoring the echoing back
        last_line = resp.split("\r\n")[-1]
        if DEBUG:
            print("last_line : %s" % repr(last_line))

        if "--More--" in last_line:    
            self.more_handler()
        else:
            try:
                self.send_server_immediate("\x08" * (len(filter(self.ascii_filter,self.client_buffer))))
                self.send_server_immediate("\x07")
                _ = self.get_server_response(self.timeout,increase_timeout=False) 
                #b = self.get_server_response(self.timeout,increase_timeout=False) 

                resp_cmd = last_line.split("#")[1]
                if len(self.client_buffer):
                    self.client_buffer = list(resp_cmd)
                    #print "SETTING SELF TO %s " % repr(resp_cmd)
                    #print "SETTING backspaces TO %s " % repr(a+b)
                    self.clear_client_buffer_display(till_cursor=False)
                    self.client.send(resp_cmd)
                    self.cursor_index = len(self.client_buffer)
                   
            except Exception as e:

                resp_cmd = last_line.split(">")[1]
                if len(self.client_buffer):
                    self.client_buffer = list(resp_cmd)
                    #print "SETTING SELF TO %s " % repr(resp_cmd)
                    #print "SETTING backspaces TO %s " % repr(a+b)
                    self.clear_client_buffer_display(till_cursor=False)
                    self.client.send(resp_cmd)
                    self.cursor_index = len(self.client_buffer)
                    
             

        #print "CURR CLIE: %s" % self.client_buffer
    
    # With Cisco tab complete, >1 and 0 both just echo
    # prompt and cli_buff back (e.g. cli>x )
    # Valid completion seems to behave the same as linux
    def tab_complete(self,tab="\t"): 
        self.send_server_immediate(''.join(self.client_buffer) + tab)

        buff = ""
        resp = " "
        # discard/deal with null responses and server echo
        while len(resp):
            resp = self.get_server_response(self.timeout,increase_timeout=False)         
            if not len(resp):
                break
            buff += resp 

        tmp = ''.join(self.client_buffer)
        if DEBUG:
            print("TMP: %s" % repr(tmp))
            print(repr(buff))

        # Case 1: No completion was found or >1 completion
        try:
            if (buff.split(">")[1] == tmp) or (buff.split("#")[1] == tmp): 
                if DEBUG:
                    print("path2")
                self.client.send("\x08" * (len(filter(self.ascii_filter,self.client_buffer))))
                self.client.send("\x07")
                self.client.send(tmp)
                return
            else: # no match => valid competion
                pass
        except:
            # case 3: Valid Completion was found
            if DEBUG:
                print("path1")
            self.cursor_index = len(self.client_buffer)

            # to clear out both buffers
            self.server.send("\x03") 
            ret = " "
            while len(ret):
                ret = self.get_server_response(self.timeout,increase_timeout=False)         

            # clear old buffer
            self.client.send("\x08" * (len(filter(self.ascii_filter,self.client_buffer))))
            self.client.send("\x07")
        
            self.client.send(buff)
            if DEBUG:
                print(repr(buff))
            # in order to find where the completion is located accurately,
            # search from left, discard first instance of client buffer
            # e.g. 'en\r\nasig1-oob1>enable '
            completion_index = buff[len(self.client_buffer):].find(''.join(self.client_buffer)) + len(self.client_buffer)
            self.client_buffer = list(buff[completion_index:]) 
            self.cursor_index = len(self.client_buffer)
    
            if DEBUG:
                print("Client Response: %s" % ''.join(self.client_buffer))


    def set_hijack_flag(self):
        self.hijack_flag = True
        
    def clear_hijack_flag(self):
        self.hijack_flag = False
        
    def disable_or_quit(self):
        if self.enable == True:
            self.enable = False
        else:
            self.set_hijack_flag() 


    def set_enable_mode(self):
        self.enable = True

    def newline(self): 
        
        # need this for enable. Reset echoing on "\r" 
        if self.echo_flag == False:
            self.echo_flag = True

        if len(self.client_buffer) and not self.arrow_flag: 
            tmp = ''.join(self.client_buffer[:]) + "\r"
            self.client_buffer = []
            self.cursor_index = 0
            return tmp
        elif len(self.client_buffer) and self.arrow_flag:
            self.arrow_flag = False
            ret = self.get_server_response(self.timeout,increase_timeout=False)         
            #print "ret: %s" % repr(ret)
            self.server.send("\x03")
            ret = self.get_server_response(self.timeout,increase_timeout=False)         
            #print "ret: %s" % repr(ret)
            tmp = ''.join(self.client_buffer[:]) + "\r"
            self.client_buffer = []
            self.cursor_index = 0
            return tmp
        else:
            self.passthrough("\r")
            self.arrow_flag = False

