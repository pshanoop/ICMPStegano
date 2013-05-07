/* 
 * File:   IcmpStegano.h
 * Author: Sanoop Pattanath
 *
 * Created on February 13, 2013, 5:19 PM
 * Description : 
 *  Class used to Send or Receive data  through ICMPv4 Protocol 
 * 
 * Mode :
 *  Burst :  Uses sequence(2 bytes) identifier (2 bytes) and data (56 bytes)  fields.
 *               Total Hidden data in a packet  2 + 2 + 56 = 60 Bytes =  480 bits
 * 
 *  Secure: Uses sequence(2 bytes) and identifier (2 bytes)  fields.
 *               Total Hidden data in a packet  2 + 2  = 4 Bytes = 32 bits
 * 
 * Note : Please compile this code with -pthread parameter.
 * Warning: Socket creation fails if the current use is not super user. Please use su or sudo command
 * 
 */

#ifndef ICMPSTEGANO_H
#define	ICMPSTEGANO_H

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>

#include <iostream>
#include <string.h>
#include <cmath>
#include <cstdio>
#include "msgqueue.h"


#ifndef PACKETSIZE
#define PACKETSIZE 64
#endif          /*PACKETSIZE*/

#ifndef  STEGANO_MODE
#define STEGANO_RESV -1
#define STEGANO_MODE 0
#define STEGANO_BURST 1
#define STEGANO_SECURE 2

// Communication initial 
#define STEGANO_VER 0
#define STEGANO_LEN 1
#define STEGANO_INIT 2
#define STEGANO_SEND 3
#define STEGANO_ECHO 4
#define STEGANO_RECV 2
#endif /*STEGANO_MODE*/

#define STEGANO_IPC_IN 999   // just a random number for message queue
#define STEGANO_IPC_OUT 777  // another random number for message queue

#ifndef __BYTE_ORDER
# error	"Please fix <endian.h>"
#elif __BYTE_ORDER == __BIG_ENDIAN
#warning        "This class not designed for Big Endian processors. Use at your own risk"
#endif


#define STEGANO_FMAX  4294967295 // Maximum file size that can be send thorugh (4GB)
#define DATA_LEN 4+PACKETSIZE-sizeof(struct icmphdr) // 4bytes for seq + id and 
                                                     // remaining data optional field 
                                                     // which is used in burst mode
struct packet
{
	struct icmphdr hdr;
	char msg[PACKETSIZE-sizeof(struct icmphdr)];  // Calculating data length size
};
typedef struct 
{
      u_int8_t type;		/* message type */
      u_int8_t code;		/* type sub-code */
      u_int16_t checksum;
      unsigned char data[DATA_LEN];     // stegano data field
}cpacket;  // custom packet for steganography


// To store  size of file to send
typedef union {
    unsigned int bytes;    
    struct b16{
        u_int16_t lsb; // 2bytes
        u_int16_t msb; // 2 bytes
    }ub16;
    unsigned char bindata[4];
}Stegano_fsize;

class IcmpStegano {
public:    
    // Initializer
    IcmpStegano();
    IcmpStegano(const IcmpStegano& orig);
    IcmpStegano(const char ip [],const unsigned short cmode);       
    // Deleting 
    virtual ~IcmpStegano();    
    void display(void *buf,int bytes);
    void display(int test);
    void Icmp_Receive(void);
    void Icmp_ReceiveFile(void);
    void Icmp_Send(void); // mode gives init send and data send
    unsigned int Icmp_SendFileSize(void);
    unsigned int Icmp_GetFileSize(void);
    short Icmp_SendFile(void);
    double Get_Current_Pkt(void); // returns current packet sent
    void SetMode(const unsigned short mode); // TO set mode of steganography
    void SetFname(const char fname[]);
    void SetQid(long _in,long _out); // sets message queue id(s)
    unsigned short GetMode(void); 
    unsigned short Is_Alive(const char* hostname); // TODO: Check usage
    
    static void *IPCWatcher(void * arg); // thread runnable for IPC message queue in
    static void *IPCSender(void *arg); // thread runnable for status 
   // void Icmp_Send(struct sockaddr_in *addr);
    unsigned short Get_Error(void);
    
   
private:   
  int pid; //process id
  
  static msgqueue *msg_in;// message queue object for cmd input
  static msgqueue *msg_out;//message queue object for status output
  int recv_fd; //received file Descriptor
  int send_fd; //send file Descriptor
  int sd; // Socket Descriptor
  struct protoent *proto;
  unsigned int fsize;
  unsigned int wsize; // size of data remaining to write
  double no_of_packet; // total number of packet
  double current_packet; // current sent packet
  static int current_progress;  
  static unsigned short stop_flag; // flag used to stop sending or receiving
  pthread_t thWatcher,thSender; 
  
  struct hostent *sndhname;  //  Sender host name
  //struct hostent *rcvhname; // Receiver host name 
  struct hostent *fhname;; // to store foreign host name send/receive
  struct sockaddr_in addr; // socket send
  struct sockaddr_in r_addr; //socket for receive
  
  unsigned short mode;   // Mode of Steganography  
  unsigned short cmode; // communication mode  
  char fname[255]; // To store file name
  
  cpacket snd_packet; // custom packet for sending
  
  
  unsigned char SndPktBuffer[PACKETSIZE+20];  // IPv4 header + ICMP packet size for sender
  unsigned char RcvPktBuffer[PACKETSIZE+20]; // IPv4 header + ICMP packet size for receiver
  unsigned char data_buffer[DATA_LEN]; // buffer file reading and creating
  
  unsigned short Stegano_Error;  //Error flag variable 
  
  unsigned short checksum(void *b, int len);
  unsigned int GetFileSize(void); // returns file size
  void IPCSend();
  
  unsigned short IsRecvd_BO(void)    ;  // Matches send packet and received packet
  void InsertData_BO();
  unsigned short ExtractData_BO(void);
  unsigned int ExtractFileSize_BO(void); 
  unsigned short ReadFile_BO(void); // function to read the file
  unsigned short WriteFile_BO(void); // To recreate file
  
};


#endif	/* ICMPSTEGANO_H */

