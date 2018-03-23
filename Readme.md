# Decept Proxy

Yay, another network proxy. What makes this any different from any others?

* Created with portability in mind, it only uses as standard python libraries,
so you can drop it on a box and not worry, as long as python 2 is there.

* Supports SSL endpoirnts, IPV6, Unix Sockets, Abstract Namespace sockets,
L3 protocols/captures and also L2 bridging and passive modes.

* Any traffic that passes through Decept.py can be dumped into a .fuzzer file
format that is suitable for fuzzing with the Mutiny Fuzzing Framework.

* SSH proxying/sniffing/filtering with lil_sshniffer.py and lil_netkit.py  

* HTTP/HTTPS multiplexing. Examine hosts.conf for more information.

* Based off of the tcp proxy.py from Black Hat Python by Justin Seitz

```
usage: decept.py <local_host> <local_port> <remote_host> <remote_port> [OPTIONS]

optional arguments:
  -h, --help            show this help message and exit
  --recv_first          Receive stuff first?
  --timeout TIMEOUT     Timeout for outbound socket
  --loglast LOGLAST     Log the last packet (unimplimented)
  --pcapdir PCAPDIR     Directory to store pcaps (extensions required)
  --pps                 Create a new pcap for each session
  --snaplen SNAPLEN     Length of packet truncation
  --fuzzer FUZZFILE     *.fuzzer output for mutiny (extensions required)
  --dumpraw DUMPDIR     Directory to dump raw packet files into
                        (fmt = %d-%s % (pkt_num,[inbound|outbound]))
  --l_abstract          Treat local socket as abstract namespace socket
  --r_abstract          Treat remote socket as abstract namespace socket


L4 options:
  -l, --localEnd {ssl,udp,unix,tcp,unix_udp}
                        Local endpoint type
  -r, --remoteEnd {ssl,udp,unix,tcp,unix_udp}
                        Remote endpoint type

L3 options:
  --L3_proto PROTO      L3 proxy, PROTO=>raw to access >= L3 (IPHDR_INCL=1)
                        otherwise, set Proto to OSPF/EIGRP/etc... and kernel
                        will craft the headers up till the protocol itself

L2 usage: decept.py <local_int> <local_mac> <remote_int> <remote_mac>

L2 options:

  --l2_filter MACADDR   Ignore inbound traffic except from MACADDR
  --l2_MTU    MTU       Set Maximum Transmision Unit for socket
  --l2_forward          Bridge the local interface and remote interface

L4 Usage: decept.py 127.0.0.1 9999 10.0.0.1 8080
L3 Usage: decept.py 127.0.0.1 0 10.0.0.1 0 --L3_proto OSPF
L2 Usage: decept.py lo 00:00:00:00:00:00 eth0 ff:aa:cc:ee:dd:00
```

# lil_sshniffer.py

Main lil_sshniffer uses:

1. SSH MITM: With the '--sniff' flag, lil_sshniffer will accept an SSH connection
on the Localhost/local port specified and then try to connect to the given RHOST/RPORT with the
credentials provided. All traffic is logged and can be filtered/acted upon before traversing all
the way through with the '--filter' flag (lil_netkit.py for more info). 

2. Fuzzing an SSH wrapped service: Without the '-s' flag, lil_sshniffer will take a connection
and wrap in in whatever type of SSH connection you want. (--subsystem/--pty/--interactive/
--pty) 

```
[^.^] lil_sshniffer.py [^.^] ~For all your sshniffing needs~

usage: lil_sshniffer.py rhost
                        [-h] [--lhost LHOST] [--lport LPORT] [--rport RPORT]
                        [-d] [-l] [-P] [-s] [-k SPOOF_KEY] [-r] [-a AUTH_KEY]
                        [-u USERNAME] [-p PASSWORD] [-t TIMEOUT]
                        [--subsystem SUBSYSTEM | --execute EXECUTE | --interactive]
                        [-f] [-?] [-j]

positional arguments:
  rhost                 Remote address to connect to

optional arguments:
  -h, --help            show this help message and exit
  --lhost LHOST         Local address to bind to
  --lport LPORT         Local port to bind to
  --rport RPORT         Remote port to connect to
  -d, --debug           Extra output
  -l, --logging         Enable/disable logging
  -P, --pty             Allocate a pty also
  -s, --sniff           Create an inbound and outbound SSH Server
  -k SPOOF_KEY, --spoof_key SPOOF_KEY
                        RSA key to use for spoofing
  -r, --retry           Do the retry hack >_<
  -a AUTH_KEY, --auth_key AUTH_KEY
                        Key for authenticating outbound
  -u USERNAME, --username USERNAME
                        Username for outbound connection (leave blank for
                        prompt)
  -p PASSWORD, --password PASSWORD
                        Password for outbound connection (leave blank for
                        prompt)
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout for sockets
  --subsystem SUBSYSTEM, -S SUBSYSTEM
                        Execute the given subsystem (scp/sftp/ssh/netconf/etc)
  --execute EXECUTE, -e EXECUTE
                        Execute a single command
  --interactive, -i     Requests a shell w/pty (default)
  -f, --filtering       Filter input and output w/lil_netkit
  -?, --cisco           For when you're filtering on a connection with a Cisco
                        CLI device
  -j, --hijack          Hijack ssh session after target quits
```

