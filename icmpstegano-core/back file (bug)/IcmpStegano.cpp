/* 
 * File:   IcmpStegano.cpp
 * Author: Sanoop Pattanath
 * 
 * Created on February 13, 2013, 5:19 PM
 */

#include <stdlib.h>
#include <sstream>

#include "IcmpStegano.h"

unsigned short IcmpStegano::stop_flag = 0;
msgqueue* IcmpStegano::msg_in = NULL;
msgqueue* IcmpStegano::msg_out = NULL;
int IcmpStegano::current_progress=0;
IcmpStegano::IcmpStegano() {
    //TODO
    this->pid = -1;
    //All pointer is initialized to null
    this->proto = NULL;
    this->sndhname = NULL;
    //this->rcvhname = NULL;
    this->fhname = NULL;
    this->fsize = 0;
    this->no_of_packet = 0;
    this->current_packet = 0;    

    // Clearing buffers  and structures to zero bits;
    bzero(this->SndPktBuffer, sizeof (this->SndPktBuffer));
    bzero(this->RcvPktBuffer, sizeof (this->RcvPktBuffer));
    bzero(this->data_buffer, sizeof (this->data_buffer));
    bzero(this->fname, sizeof (this->fname));
    bzero(&this->addr, sizeof (this->addr));

}

IcmpStegano::IcmpStegano(const IcmpStegano& orig) {
    //TODO

}

double IcmpStegano::Get_Current_Pkt() {return this->current_packet;}

IcmpStegano::IcmpStegano(const char ip[], const unsigned short cmode) {
    const int val = 255; // For TTL
    this->cmode = cmode;
    this->proto = getprotobyname("ICMP");
    this->fhname = gethostbyname(ip);
    this->addr.sin_family = fhname->h_addrtype;
    this->addr.sin_port = 0;
    //ref static_cast<struct iphdr*>
    this->addr.sin_addr.s_addr = *(long *) this->fhname->h_addr;
    
    this->sd = socket(PF_INET, SOCK_RAW, proto->p_proto);
        if (sd < 0) {
            std::cerr << "socket creation for send fail !!! :(";
            return;
        }
    if (this->cmode == STEGANO_SEND) {
        
        if (setsockopt(sd, SOL_IP, IP_TTL, &val, sizeof (val)) != 0)
            std::cerr << "Set TTL failed!!! :(";
        if (fcntl(sd, F_SETFL, O_NONBLOCK) != 0)
            std::cerr << "Request non blocking failed!!! :(";
    } else if (this->cmode == STEGANO_RECV) {
        bzero(this->RcvPktBuffer,sizeof(this->RcvPktBuffer));
        
    }

}

void IcmpStegano::display(void *buf, int bytes) {

    int i;
    //unsigned char data[] = "\x45\x0\x0\x54\x31\x8F\x0\x0\x40\x1\x4B\x18\x7F\x0\x0\x1\x7F\x0\x0\x1\x0\x0\x84\xE\x20\x0\x20\x0\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F\x60\x61\x62\x63\x64\x65\x66\x0";
    //        buf = data;
    struct iphdr* ip = static_cast<struct iphdr*> (buf); // explicit type casting
    struct icmphdr *icmp = static_cast<struct icmphdr*> (buf + ip->ihl * 4);
    unsigned int icmptype = icmp->code;
    unsigned char *data = static_cast<unsigned char *> (buf + ip->ihl * 4 + sizeof (icmp));
    //unsigned char *stdata =static_cast<unsigned char *> (buf+25);
    printf("----------------\n");
    for (i = 0; i < bytes; i++) {
        if (!(i & 15)) printf("\n %X:  ", i);
        printf(" %X ", ((unsigned char*) buf)[i]);
    }
    printf("\n");
    unsigned int ver = ip->version;
    unsigned int saddr = ip->saddr;
    char str_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, str_ip, INET_ADDRSTRLEN);

    printf("\n Version : %d Sender IP: %d SenderIP"
            ":%s icmp type:%d", ver, saddr, str_ip, icmptype);

    printf("\n sequece : %x id: %x \n", icmp->un.echo.id, icmp->un.echo.sequence);
    for (i = 24; i < bytes; i++) {
        //if ( !(i & 15) ) printf("\n %X:  ", i);
        printf(" %X ", ((unsigned char*) buf)[i]);
    }

    //printf("\n DATA : %s",data);


}

void IcmpStegano::display(int test) {
    Stegano_fsize filesize;
    //filesize.bytes = GetFileSize();
    unsigned char bin[] = "\x4a\x2\x0\x0\x0";
    switch (test) {
        case 1:
            std::cout << std::endl << GetFileSize();
            break;
        case 2:

            memcpy(static_cast<unsigned char *> (filesize.bindata),
                           static_cast<unsigned char *> (bin), 4);
            std::cout << std::endl << filesize.bytes << " ASCII : " << filesize.bindata << std::endl;
            for (int i = 0; i < 5; i++)
                printf("%x ", filesize.bindata[i]);
            break;

        default:
            std::cout << std::endl << "test case is invalid";
    }
}
//Returns 0 or 1
unsigned short IcmpStegano::ExtractData_BO(void){
    struct iphdr *ip = reinterpret_cast<struct iphdr*> (this->RcvPktBuffer);  // Ip header extraction
    cpacket *icmpcpkt = reinterpret_cast <cpacket *> (this->RcvPktBuffer + ip->ihl * 4); //icmp header extraction
    // Extraction of Stegano DATA
    memcpy(this->data_buffer,icmpcpkt->data,DATA_LEN);
    if(sizeof(icmpcpkt->data))
        return 1;
    else
        return 0;
}
unsigned int IcmpStegano::Icmp_GetFileSize(void){
    this->Icmp_Receive(); // Gets a packet;    
    this->ExtractData_BO(); // Get Stegano data to buffer
      // Start thread watcher
    int ret = pthread_create(&this->thWatcher, NULL,&IcmpStegano::IPCWatcher, NULL);   
    if(ret == -1)
        std::cerr<<"\n Watcher Thread create failed !!!\n";    
    return this->ExtractFileSize_BO(); // Gets the file size    
}

// Extracts files size using Stegano_fsize
unsigned int IcmpStegano::ExtractFileSize_BO(void){
    Stegano_fsize fsize;
    memcpy(static_cast<unsigned char *>(fsize.bindata),
                  static_cast<unsigned char *>(this->data_buffer),4);
    this->fsize = fsize.bytes;
    return fsize.bytes;
}
// Receives a icmp echo packet from foreign ip 
void IcmpStegano::Icmp_Receive(void) {
    int bytes;
    int len = sizeof(this->r_addr);   
    cpacket *icmpcpkt = NULL;
    struct iphdr *ip = NULL;
    unsigned short  flag =0;
    u_int32_t addrs; // stores long ip of system    
    memcpy(&addrs,this->fhname->h_addr_list[0],this->fhname->h_length);
    while(!flag){ // receive until foreign echo packet  comes
            
        bytes = recvfrom(this->sd,this->RcvPktBuffer,sizeof(this->RcvPktBuffer),
                              0,(struct sockaddr*)&(this->r_addr),(socklen_t *)&len);    
        if(bytes >0)
        {
           // IP header extraction
            ip = reinterpret_cast<struct iphdr*> (this->RcvPktBuffer);  
            //ICMP header extraction
            icmpcpkt  = reinterpret_cast <cpacket *> (this->RcvPktBuffer + ip->ihl * 4); 
            //received only if the packet is echo request and from foreign IP
            if(addrs == ip->saddr && icmpcpkt->type == 8){
                std::cout<<"\nForeign ip: "<<addrs;        
                std::cout<<"\nSender ip:"<<ip->saddr; 
                std::cout<<"\nData received"
                         <<"\nSize : " << bytes
                         <<std::endl;
                flag =1; // stop receiving
            }
          else //clear the buffer
                bzero(this->data_buffer,sizeof(this->data_buffer));                         
        }                
    }
}
void IcmpStegano::Icmp_ReceiveFile(void) {
    double len = DATA_LEN;           
    this->current_packet = 0;   
    this->wsize = this->fsize;
    
    double i;    
    if(this->mode == STEGANO_SECURE){
        this->no_of_packet = ceil((double)this->fsize / 4 ); 
        std::cout <<"\nFSize: " << this->fsize;
        std::cout <<"\nNo_of_Packet: " << this->no_of_packet;        
    }
    else if(this->mode == STEGANO_BURST){        
        this->no_of_packet = ceil((double)this->fsize / len);
        std::cout << "\nFSize: " << this->fsize;
        std::cout << "\nNo_of_Packet (4): " << this->no_of_packet;        
    }
    else{
        std::cerr << "\n Set Steganography mode first";        
        return;
    }
    std::cout<<"\nTotal no of packet :"<<this->no_of_packet;   
    for(i=1;i<=this->no_of_packet && !stop_flag;i++){
         this->Icmp_Receive();
         std::cout<<"\nPacket: "<<i;
        if(this->ExtractData_BO()){
            this->current_packet=i;            
            //writing into file 
            this->WriteFile_BO();
            current_progress = (int ) ((this->current_packet/this->no_of_packet)*100);  
            this->IPCSend(); // send status            
            std::cout<<std::endl<<"Packet ("<<this->current_packet
                <<" of "<< this->no_of_packet<<") ["
                <<current_progress<<"%] done";                        
        }
        else{        
            std::cerr<<"\n Receive(length) Error Failed!!! :(";
            break;
        }         
    }
    if(stop_flag){
        std::cerr<<"Communication Aborted by User !!!";      
    }    
    current_progress=-1;
    this->IPCSend(); //send stop to parent thread            
}

unsigned int IcmpStegano::Icmp_SendFileSize(void) {    
    Stegano_fsize filesize;
    int ret = pthread_create(&this->thWatcher, NULL,&IcmpStegano::IPCWatcher, NULL);
    if(ret == -1)
        std::cerr<<"\n Watcher Thread create failed !!!\n";
    ret = pthread_create(&this->thSender, NULL,&IcmpStegano::IPCSender, NULL);   
    if(ret == -1)
        std::cerr<<"\n Status Thread create failed !!!\n";
    this->fsize = filesize.bytes = GetFileSize();
    memcpy(this->data_buffer, filesize.bindata, sizeof (filesize.bindata));
    for (int i = 4; i < DATA_LEN; i++)
        data_buffer[i] = i + 'A';
    this->InsertData_BO();    
    this->Icmp_Send();
    current_progress = 1; // update progress to 1 %
    return filesize.bytes;
}
short IcmpStegano::Icmp_SendFile() {
    double len = DATA_LEN;
    if (this->mode == STEGANO_BURST) {
        this->no_of_packet = ceil((double)this->fsize / len);
        std::cout << "\n Debug: DATA_LEN: " << DATA_LEN;
        std::cout << "\n Debug: FSize: " << this->fsize;
        std::cout << "\n Debug: No_of_Packet: " << this->no_of_packet; 
    } else if (this->mode == STEGANO_SECURE){
        this->no_of_packet = ceil((double)this->fsize / 4);
        std::cout << "\n Debug: FSize: " << this->fsize;
        std::cout << "\n Debug: No_of_Packet (4): " << this->no_of_packet;
    }
    else {
        std::cerr << "\n Set Steganography mode first";
        return 0;
    }
    for (double i = 1; i<= this->no_of_packet && !stop_flag ; i++) {
        this->ReadFile_BO();
        this->InsertData_BO();        
        this->Icmp_Send();
        this->current_packet = i;
        current_progress = (int ) ((this->current_packet/this->no_of_packet)*100);
        std::cout<<std::endl<<"Packet ("<<this->current_packet
                <<" of "<< this->no_of_packet<<") ["
                <<current_progress<<"%] done";  
        this->IPCSend(); // send status        
        sleep(2);
    }    
    if(stop_flag)
        std::cerr<<"Communication Aborted by User !!!";          
    current_progress=-1;
    this->IPCSend(); //send stop to parent thread        
    return (stop_flag)?-1:1;
}

unsigned short IcmpStegano::ReadFile_BO() {
    // Clear buffer..
    bzero(this->data_buffer, sizeof (this->data_buffer));
    if (this->mode == STEGANO_BURST)
        return read(this->send_fd, this->data_buffer, sizeof (this->data_buffer));
    else if (this->mode == STEGANO_SECURE) {
        read(this->send_fd, this->data_buffer, sizeof (unsigned char) * 4);
        for (int i = 4; i < DATA_LEN; i++)
            data_buffer[i] = i + '0';
        return 4;
    } else
        std::cerr << "\n Set Steganography mode first";
    return 0;
}
unsigned short IcmpStegano::WriteFile_BO(void){
    // A lot to do
    int size_of_data =0; // size data to write
    int data_len = DATA_LEN;
    std::cout<<"\n Remaining write size: "<<this->wsize;
    if(this->mode == STEGANO_BURST){
        if(this->wsize <= data_len)
            size_of_data = this->wsize;
        else{
            size_of_data =data_len;
            this->wsize -= data_len;        
        }        
        return write(this->recv_fd,this->data_buffer,size_of_data);   
    }
    else if(this->mode == STEGANO_SECURE){     
        if(this->wsize <=  4)
            size_of_data = this->wsize;
        else{
            size_of_data = 4;
            this->wsize -= 4;
        }        
        return write(this->recv_fd,this->data_buffer,size_of_data);
    }    
    else
        std::cerr<<"\n Set Steganography mode first or set file";
    return 0;
}

void IcmpStegano::SetFname(const char fname[]) {
    strcpy(this->fname, fname);
    std::cout<< this->fname;
    if (this->cmode == STEGANO_SEND){
       if((this->send_fd = open(this->fname, O_RDONLY)) == -1)
       {
            perror("\n send fd faild!!! :(");
            exit(EXIT_FAILURE);
       }
    }
    else if (this->cmode == STEGANO_RECV){
        if((this->recv_fd = open(fname,O_CREAT|O_TRUNC| O_WRONLY,0664))== -1)
        {
            perror("\n recv fd faild!!! :(");
            exit(EXIT_FAILURE);
        }
    }
    else
        std::cerr << "\n Set communication mode first";
}

unsigned int IcmpStegano::GetFileSize(void) {
    struct stat filestatus;
    stat(this->fname, &filestatus);
    return filestatus.st_size;
}


//sends the packet
void IcmpStegano::Icmp_Send(void) {
    if(! stop_flag){
        if (sendto(this->sd, &(this->snd_packet), sizeof (this->snd_packet), 0, (struct sockaddr *) (&this->addr), sizeof (this->addr)) <= 0)
           std::cerr << "\n sendto function failed !!! :(";
    }
}

unsigned short IcmpStegano::checksum(void *b, int len) {

    unsigned short *buf = static_cast<unsigned short*> (b);
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*) buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Returns Error code

unsigned short IcmpStegano::Get_Error(void) {
    return this->Stegano_Error;
}

unsigned short IcmpStegano::Is_Alive(const char* hostname) {
    //TODO
    return 0;
}

unsigned short IcmpStegano::IsRecvd_BO(void) {
    void *sndbuf = this->SndPktBuffer;
    void *rcvbuf = this->RcvPktBuffer;
    // TODO    
    return 1;
}

void IcmpStegano::SetMode(const unsigned short mode) {this->mode = mode;}

void IcmpStegano::SetQid(long _in, long _out){
    msg_in= new msgqueue(_in); msg_out = new msgqueue(_out);
}

unsigned short IcmpStegano::GetMode(void) {return this->mode;}

void IcmpStegano::InsertData_BO(void) {
    //Packet creation
    bzero(&this->snd_packet, sizeof (this->snd_packet));
    this->snd_packet.type = ICMP_ECHO;
    
    // Inserting data to stegano data field in custom packet
    memcpy(this->snd_packet.data, this->data_buffer, sizeof (this->data_buffer));

    // calculating checksum
    this->snd_packet.checksum = this->checksum(&(this->snd_packet), sizeof ((this->snd_packet)));
}

void * IcmpStegano::IPCWatcher(void* arg){    
    char msgbuf[MAX_SEND_SIZE];
    msg_in->read_message(STEGANO_IPC_IN,msgbuf);    
    //std::cout<<msgbuf;
    if(!strcmp(msgbuf,"stop"))
        stop_flag = 1; // set stop flag to stop sending file
    pthread_exit(NULL); 
}
void IcmpStegano::IPCSend(){    
    std::stringstream temp;
    std::string temp2;
    char buf[MAX_SEND_SIZE];
    if(current_progress <101 ){          
        //int to string convert
        temp<<current_progress;
        temp2 = temp.str();
        strcpy(buf,temp2.c_str());
        msg_out->send_message(STEGANO_IPC_OUT,buf);                
    }    
}

void * IcmpStegano::IPCSender(void* arg){    
//    std::stringstream temp;
//    std::string temp2;
//    char buf[MAX_SEND_SIZE];
//    while(current_progress !=100 ){          
//        //int to string convert
//        temp<<current_progress;
//        temp2 = temp.str();
//        strcat(buf,temp2.c_str());
//        msg_out->send_message(STEGANO_IPC_OUT,buf);                
//    }
//    std::cout<<std::endl<<"Thread exited !!!";
    pthread_exit(NULL); 
}

IcmpStegano::~IcmpStegano() {
    
    //close file descriptors 
    
    int retval;
    if(this->cmode== STEGANO_RECV){
      while(retval = fsync(this->recv_fd),retval == -1)
            std::cerr<<"Data not written";        
      while (retval = close(this->recv_fd), retval == -1 && errno == EINTR) ;
    } else if (this->cmode == STEGANO_SEND)
      while (retval = close(this->send_fd), retval == -1 && errno == EINTR) ;
    
    while(retval = close(this->sd), retval == -1 && errno == EINTR); //closing socket 
     
    //Deleting all allocated memory
    delete msg_in;
    delete msg_out;
    
    
    //TODO
}



