moufoDNS
========
Pseudo DNS server

ABOUT
-----
moufoDNS is a tiny pseudo DNS server that can be easily configured to 
return only a certain IP address no matter what. This is useful for
setting up a hotspot-like environment with minimal configuration and
minimal software support.
It can also act as a DNS proxy, by asking other DNS servers for certain
requests.
It is fully configurable by command line options or by a configuration file

** This is NOT an industrial-strength tool and should not be used as such ***


USAGE
-----
To set up your hotspot-like environment you need 3 things:
1. A web server running on an IP address, hosting the hotstpot web page.
   For our example this web server will be on 10.140.6.66
2. moufodns running on a pc, configured to return by default the IP address of
   the web server. That is 10.140.6.66. The moufodns and web server could
   also be on the same pc, but in our example moufodns runs on 10.140.1.1.
3. Your Access Point's dhcp server must be configured so that the DNS server
   it distributes is the moufodns pc's IP. In our example it is 10.140.1.1

Here is how it works:
So when a wireless client asks the AP dhcp server for a DNS server, the AP
returns 10.140.1.1 which is the IP of the moufo-dns server.
From that point on, the client is on the pseudo-hotspot.
If the client tries to open any website on its browser, the DNS request will
go through moufodns. Lets say client asks for http://www.alpha.beta. Moufodns
will return 10.140.6.66 and therefore the browser will open the Hotspot web
page instead of the real www.alpha.beta.

The reason we call the whole setup as a "pseudo"-hotspot is because the client
is free to access the local network without any authentication required. Real
hotspots can be configured to block access to the network.
But there are situations where such authentication is not required and in fact
is not wanted. For example in the wireless community context it makes no sense
to block access to the free network at the hotspot level.



                        LAN
            WiFi         |
   client - - - - -> AP -| 
IP : 10.140.X.Y          |-Web Server 10.140.6.66
DNS: 10.140.1.1          |
                         |-MoufoDNS Server 10.140.1.1
                         |

1. client connects to AP
2. AP dhcp server assigns it IP: 10.140.X.Y and DNS: 10.140.1.1
3. Now client has access to the full network.
4. client asks for http://www.any.page on a web browser
5. MoufoDNS (10.140.1.1) replies that www.any.page is @ 10.140.6.66
6. client is fooled to think that any.page is in 10.140.6.66
7. client opens the pseudo-hotspot web page from 10.140.6.66



FEATURES
--------
o Configurable behavior by command line arguments and config file.
o Verbose output, prints all details of each DNS request received by the
  moufoDNS server, including date and time.
o Supports dumping to log file which can be later parsed for statistics.
o Filtering of the output that goes to the log file by blac/white lists.



                +---------+
DNS requests -> |Moufo DNS| -> stdout
                +---------+
                     |
                 filters -> log file

