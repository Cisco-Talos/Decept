#!/usr/bin/python  
import sys
import os
import os.path   
import multiprocessing

try:
    path = os.path.join(os.path.abspath('.'),"..")
    sys.path.append(path)
    import lil_netkit
    
except Exception as e:
    print str(e)
    print "[x.x] Couldn't import decept, exiting"
    sys.exit()


#decept proxy prototype
#def __init__(self,lhost,lport,rhost,rport,local_end_type,remote_end_type,receive_first=False):

def main():

    b = multiprocessing.Event()
    a = lil_netkit.lil_netkit(b)
    print "INPUT: %s"%str(sys.argv[1:])
    print "OUTBOUND"
    print a.outbound_filter(" ".join(sys.argv[1:]))
    print "INBOUND"
    print a.inbound_filter(" ".join(sys.argv[1:]))
    print a.EventFlag.is_set()
    
    
if __name__ == "__main__":
    main()
