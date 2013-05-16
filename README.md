ICMPStegano
=========================== 
Network Steganography tool for *ICMP protocol* with good **Qt GUI**. The Qt GUI also provide good compression using `zlib` library and `AES_265_CBC` encryption for the files to make more secured communication.

The whole program is in two layers Application Layer (GUI,Cryptography,Compression), Network Layer (ICMP Steganography). Both layers are separate programs which communicate each other by using Unix IPC message queue. This tool provides two mode of steganography they are following.

+ **Secure :-**

>In each ICMP packet `4 bytes` of hidden data can be inserted. The hidden data will be placed in both `Identifier (2 bytes) and Sequence number (2 bytes)` fields. This is more secure than burst mode but transfer speed will be very slow.

+ **Burst :-**

>In each ICMP packet `60 bytes` of hidden data can be inserted. The hidden data will be placed Identifier (2 bytes), Sequence number (2 bytes) fields and `optional data field` ( The size depend on the packet size). This packet size can be changed by using **PACKETSIZE** (default value is 64) macro in > IcmpStegano.h. The size of hidden data can be found using macro **DATA_LEN**. *Maximum packet size is 65515 bytes (65535 - 20 = 65515, where 20 is for IPv4 header size and 65535 is the maximum size of a packet in network).*
