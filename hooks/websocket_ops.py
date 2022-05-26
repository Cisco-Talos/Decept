# http://lucumr.pocoo.org/2012/9/24/websockets-101/
# https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
'''
Frame format:  
   bytes
     0               1               2               3               4
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+
'''
ops = {
           0x0:"continuation",
           0x1:"text",
           0x2:"binary",
           # control opcodes
           0x8:"close",
           0x9:"ping",
           0xA:"pong"
}

def outbound_hook(outbound_data,userdata=[]):
    if not outbound_data:
        return ""
    
    try:
        fin,opcode,mask,unpacked = unpack_ws_packet(outbound_data)
        #print "unpack_ws_packet ret: (%d, %d, %s)" % (fin,opcode,repr(unpacked))
        if fin == "" or mask == "" or opcode == "" or unpacked == "":
            return outbound_data

        # do ops on unpacked.  
        if fin == 0:
            if ops[opcode] == "continuation"\
            or ops[opcode] == "binary"\
            or ops[opcode] == "text": 
                # buffer that shit, yo. 
                userdata.append(unpacked)
                #print "Buffered %d websocket bytes" % len(unpacked)
                return ""

        elif fin:
            if len(userdata):
                print("Reassembled fragment message:")
                unpacked = ''.join(userdata) + unpacked  
                print(repr(unpacked))
                for i in range(0,len(userdata)):
                    userdata.pop()

            if ops[opcode] == "text":
                print (unpacked)
            elif ops[opcode] == "binary":
                print("Websocket binary dump: ")
                print("\\x" + "\\x".join([c for c in unpacked]))
            elif ops[opcode] == "close":      
                print("Websocket Close Msg")
                return outbound_data
            elif ops[opcode] == "ping":      
                print("Websocket Ping Msg")
                return outbound_data
            elif ops[opcode] == "pong":      
                print("Websocket Pong Msg")
                return outbound_data
            elif ops[opcode] == "continuation": #conintuation?
                unpacked = ''.join(userdata) + unpacked
                #print "Continuation/fin"
    
            
            ## make edits here. 



            # repack
            repacked = repack_ws_packet(opcode,mask,unpacked)

            #print "returning: %s" % repacked
            return repacked

    except Exception as e:
        print(e)
        return outbound_data

# According to the rfc, the mask should not be set here (i.e. no encoding).
# If acting as a websocket server just switch the function names of the hooks.
def inbound_hook(inbound_data,userdata=[]):
    try:
        opcode,fin,key,unpacked = unpack_ws_packet(inbound_data,server=True)
        # do ops on unpacked.  
        # 
        repacked = repack_ws_packet(opcode,mask,unpacked)
        return repacked
    except:
        return inbound_data

#### Ws code
def xor_ops(key,data,length):
    import struct
    buf = ""
    #print "xor: (0x%x,%d)" % (key,length)
    for i in range(0,length,4):
        try:
            newval = struct.unpack(">I",data[i:i+4])[0] ^ key
            buf += struct.pack(">I",newval)
        except:
            break

    for j in range(0,length%4):
        keybyte = (key&(0xFF000000>>(i*8)))
        databyte = ord(data[i+j])
        buf+= chr(keybyte^databyte)
    return buf
    

def unpack_ws_packet(data,server=False):
    import struct
    options = ord(data[0])
    fin = options >> 7
    opcode = options & 0x0F

    paylen_mask = ord(data[1]) 
    mask = paylen_mask >> 7
    payload_len = paylen_mask & 0x7F

    if mask != 1 and not server:
        print("[?.?] Non-masked message? (mask=>%d)"%mask)
     
    if payload_len == 126:
        payload_len = struct.unpack(">H",data[2:4])[0] 
        bytes_read = 4
    elif payload_len == 127:
        payload_len = struct.unpack(">Q",data[2:10])[0] 
        bytes_read = 10

    if payload_len > (len(data)): 
        print("Malformed length field: %d (actual: %d). Truncating"%(payload_len,len(data)))
        payload_len = (len(data))
        
    if mask and not server:
        mask = struct.unpack(">I",data[bytes_read:bytes_read+4])[0]
        print("fin: %d, opcode: %s, mask: 0x%x, payload_len: %d"%(fin,ops[opcode],mask,payload_len))
        bytes_read+=4  
        payload_data = data[bytes_read:]
        decoded = xor_ops(mask,payload_data,payload_len)
        return fin,opcode,mask,decoded
    elif mask and server:
        #print "Unexpeced masked message from server side..."
        return fin,opcode,mask,payload_data
    else:
        return "","","","" 
    
    
def repack_ws_packet(opcode,key,data):
    import struct
    #print "entered repack: %s,0x%x"%(ops[opcode],key)
    encoded_buf = chr(opcode+0x80)
    # mask should always be set if we get to this point 
    mask_len = 0x80
     
    out_len = len(data)
    if out_len <= 125:
        mask_len += len(data) 
        encoded_buf += chr(mask_len)
    elif out_len <= 0xFFFF:
        mask_len += 126 
        encoded_buf += chr(mask_len)
        encoded_buf+=struct.pack(">H",out_len)
    elif out_len > 0xFFFF:
        mask_len += 127
        encoded_buf += chr(mask_len)
        encoded_buf+=struct.pack(">Q",out_len)
        
    encoded_buf+=struct.pack(">I",key)
    encoded_buf += xor_ops(key,data,len(data))
    return encoded_buf
      

if __name__ == "__main__":
    buf=[]
    boop = outbound_hook("\x01\xfe\x00\x10\x16\x4c\xc4\xec\x45\x09\x8a\xa8\x1c\x2f\xab\x82",buf) 
    doop = outbound_hook("\x80\xfe\x00\x04AAAAabcd",buf)
    

