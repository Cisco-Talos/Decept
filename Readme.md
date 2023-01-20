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
[<_<] Decept proxy/sniffer [>_>]


usage: decept.py <local_host> <local_port> <remote_host> <remote_port> [OPTIONS]

optional arguments:
  -h, --help            show this help message and exit
  --quiet               Don't show hexdumps
  --recv_first          Receive stuff first?
  --timeout TIMEOUT     Timeout for outbound socket
  --loglast LOGLAST     Log the last packet (unimplimented)
  --fuzzer FUZZFILE     *.fuzzer output for mutiny (extensions required)
  --dumpraw DUMPDIR     Directory to dump raw packet files into
                        (fmt = %d-%s % (pkt_num,[inbound|outbound]))
  --max-packet-len LEN  Max amount of data per packet when sending data
  --dont_kill           For when you don't want the connection to die if
                        neither side sends packets for TIMEOUT seconds.
                        Use with --expect if you still need the session
                        to end though.
  --expect RESPCOUNT    Useful with --dont_kill. Wait for RESPCOUNT
                        responses from the remote server, and then kill
                        the connection. Good for fuzzing campaigns.

  -l, {ssl,udp,tcp}|[L3 Proto]     Local endpoint type
  -r, {ssl,udp,tcp}|[L3 Proto]     Remote endpoint type

  --rbind_addr IPADDR   IP address to use for remote side. Make sure that
                        you have the IP somewhere on an interface though.
  --rbind_port PORT     PORT to bind to for remote side.

SSL Options:
  --lcert SSL_PEM_CERT  Cert to use for accepting local SSL
                        (Optionally cert and key in one file)
  --lkey SSL_PEM_KEY    Private key for local cert
  --rcert SSL_PEM_CERT  Cert to use for connecting to remote SSL
                        (Optionally cert and key in one file)
  --rkey SSL_PEM_KEY    Private key for remote cert
  --rverify HOSTNAME    Verify remote side as host HOSTNAME before
                        connecting.

Hook Files:
  Optional function definitions for processing data between inbound
  and outbound endpoints. Can pass data between the hooks/proxy with
  the userdata parameters. Look at `hooks` folder for some examples/
  prebuilt useful things.

  --hookfile <file> | Functions imported from file:
        string outbound_hook(outbound,userdata=[]):
        string inbound_hook(outbound,userdata=[]):

Tap Mode (--tap):
    Decept will replicate any inbound/outbound traffic over localhost now
    also, such that you can view traffic that has been decrypted or processed
    by the inbound/outbound hooks in something more legit than the hexdump
    function. (e.g. tcpdump/wireshark/tshark/etc)

Host Config File:
  Optionally, instead of specifying a remote host, if you specify a valid
  filename, you can multiplex HTTP/HTTPS connections to different URLs.
  Please examine the example "hosts.conf" for more information.

------------------------------------------------------------------------

L2 usage: decept.py <local_int> <local_mac> <remote_int> <remote_mac>

L2 options:
  --l2_filter MACADDR   Ignore inbound traffic except from MACADDR
  --l2_MTU    MTU       Set Maximum Transmision Unit for socket
  --l2_forward          Bridge the local interface and remote interface

  --pcap PCAPDIR     Directory to store pcaps
  --pps                 Create a new pcap for each session
  --snaplen SNAPLEN     Length of packet truncation
  --pcap_interface IFACE  Specify which interface the packets will be
                          coming in on. "eth0" by default.

L4 Usage: decept.py 127.0.0.1 9999 10.0.0.1 8080
L3 Usage: decept.py 127.0.0.1 0 10.0.0.1 0 -l icmp -r icmp
L2 Usage: decept.py lo 00:00:00:00:00:00 eth0 ff:aa:cc:ee:dd:00
Unix: decept.py localsocketname 0 remotesocketname 0
Abstract: decept.py \\x00localsocketname 0 \\x00remotesocketname 0

Arp Poisoning options:
    --poison     <config-file>    Contains "mac1|mac2|ip1|ip2" to poison.
    --poison_int <interface>      Interface on which to poison (eth0 default)

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

