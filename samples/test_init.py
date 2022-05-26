#!/usr/bin/python  
import sys
import os
import os.path   

try:
    path = os.path.join(os.path.abspath('.'),"..")
    sys.path.append(path)
    import decept
    
except Exception as e:
    print(str(e))
    print("[x.x] Couldn't import decept, exiting")
    sys.exit()


#decept proxy prototype
#def __init__(self,lhost,lport,rhost,rport,local_end_type,remote_end_type,receive_first=False):

def main():
    proxy = decept.DeceptProxy("127.0.0.1",9999,"127.0.0.1",8888,"tcp","tcp") 
    proxy.timeout = 1
    try:
        proxy.server_loop()
    except KeyboardInterrupt:
        proxy.killswitch.set()
   
    
if __name__ == "__main__":
    main()
