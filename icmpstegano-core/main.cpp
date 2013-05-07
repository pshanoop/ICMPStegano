/* 
 * File:   main.cpp
 * Author: Shanoop Pattanath
 *
 * Created on 14 March, 2013, 12:27 AM
 */

#include <iostream>
#include "IcmpStegano.h"
#include <tclap/CmdLine.h>
#include <string>




using namespace std;

/*
 * 
 */
int main(int argc, char** argv) {
  
    char enccmd[1024]; // openssl encryption command
    IcmpStegano *icmpstegano;
    

    
    try{
        TCLAP::CmdLine cmd("Command description message",' ',"1.0 Unstable");        
        
        TCLAP::ValueArg<string> fnameArg("f","file","File to Send/Receive",true,"/tmp/test","string");
        TCLAP::ValueArg<string> ipArg("i","ip","IPv4 of Sender/Receiver",true,"127.0.0.1","string");
        TCLAP::ValueArg<string> passArg("p","passwd","Password for encryption/decryption",true,"password","string");
        TCLAP::ValueArg<int> timeoutArg("t","timeOut","Time Out for receiver in milliseconds",false,800,"Integer");
        TCLAP::ValueArg<long> IPCArg_in("O","Out","Message queue id for IPC _out",false,0,"Integer");
        TCLAP::ValueArg<long> IPCArg_out("I","In","Message queue id for IPC _int",false,0,"Integer");
        vector<string> allowed;
        allowed.push_back("secure");
        allowed.push_back("burst");
        
        TCLAP::ValuesConstraint<string> allowedVals(allowed);
        TCLAP::ValueArg<string> modeArg("m","mode","Steganography mode secure or burst. "
                                        "Burst is faster but less secure and secure is slower but more secure",true,"secure",&allowedVals);
        cmd.add(modeArg);        
        cmd.add(fnameArg);
        cmd.add(ipArg);
        cmd.add(passArg);
        cmd.add(timeoutArg);
        cmd.add(IPCArg_in);
        cmd.add(IPCArg_out);
        
        TCLAP::SwitchArg sendArg("s","send","Communication mode send or receive",false);        
        TCLAP::SwitchArg recvArg("r","receive","Communication mode send or receive",false);
        cmd.xorAdd(sendArg,recvArg);

        
        cmd.parse( argc, argv ); // parsing the arguments
        
        string fname = fnameArg.getValue();
        string ip = ipArg.getValue();
        string passwd = passArg.getValue();
        int timeout = timeoutArg.getValue();
        long ipc_in= IPCArg_in.getValue();
        long ipc_out=IPCArg_out.getValue();
        string mode = modeArg.getValue();        
        
        int cmode =0;
        
        if(sendArg.isSet())
            cmode =STEGANO_SEND;
        else if(recvArg.isSet())
            cmode =STEGANO_RECV;
        cout<<"\n Command line specified"
                <<"\n File: "<<fname
                <<"\n Ip: "<<ip
                <<"\n password: "<<passwd
                <<"\n time Out: "<<timeout
                <<"\n Fifo: "<<pipe
                <<"\n mode: "<<mode
                <<"\n cmode: "<<cmode; //2= receive, 3 = send
           /*
                * cmdline  tests  
                * -r -f /tmp/file.txt -i 192.168.0.1 -p passworded -m burst -t 600 -o test.fifo               --pass
                * -s -f /tmp/file.txt -i 192.168.0.1 -p passworded -m burst -t 600 -o test.fifo               --pass
                * -s -f /testfile.txt -i 127.0.0.1 -p password -m burst -t 600 -o test.fifo  
                * -s -f /tmp/file.txt -i 192.168.0.1 -p passworded -m burst                                   --pass
                * -s -f /tmp/file.txt -i 192.168.0.1 -p passworded -m burster                                 --pass
                * -f /tmp/file.txt -i 192.168.0.1 -p passworded -m burst                                      --pass
          */                
        int n;
        switch(cmode){
            case STEGANO_SEND:
                cout<<endl<<"Encrypting file ...";
                n = sprintf(enccmd,"openssl enc -aes-256-cbc -salt -in %s -out %s -pass pass:%s",fname.c_str(),
                           "/tmp/icmpstegano.enc",passwd.c_str());          
                cout <<endl<<"Debug Msg: "<<enccmd;
                if(system(enccmd) >= 0)
                    cout<<endl<<"File encryption completed ...";
                else{
                    cerr<<"\n openSSL failed !!! :(";
                    return EXIT_FAILURE;
                }
                   
                icmpstegano = new IcmpStegano(ip.c_str(),STEGANO_SEND);
                icmpstegano->SetFname("/tmp/icmpstegano.enc");
                icmpstegano->SetQid(ipc_in,ipc_out); // Creates message queue 
                if(icmpstegano->Icmp_SendFileSize())
                {
                    if(mode == "secure")
                      icmpstegano->SetMode(STEGANO_SECURE);
                    else if(mode == "burst")
                      icmpstegano->SetMode(STEGANO_BURST);  
                    
                     if(icmpstegano->Icmp_SendFile())
                        std::cout<<"\n File has sent successfully :)";
                     else{
                     
                        std::cerr<<"\n File send failed or stoped!!! :(";
                        std::cout<<"\n Packets Sent: "
                                <<icmpstegano->Get_Current_Pkt();
                     }                    
                }
                else{                    
                    cerr<<"Fine size send failed or stoped !!! :(";
                    return EXIT_FAILURE;
                }
                                                    
                break;
            case STEGANO_RECV:
                
                icmpstegano = new IcmpStegano(ip.c_str(),STEGANO_RECV);
                icmpstegano->SetFname("/tmp/icmpstegano.enc");
                int fsize=0;
                if((fsize=icmpstegano->Icmp_GetFileSize())!=0)
                {
                    if(mode == "secure")
                      icmpstegano->SetMode(STEGANO_SECURE);
                    else if(mode == "burst")
                      icmpstegano->SetMode(STEGANO_BURST);                      
                    icmpstegano->Icmp_ReceiveFile();
                    std::cout<<"\n File has received successfully :)";               
                }
                else{                    
                    cerr<<"Fine size send failed !!! :(";
                    return EXIT_FAILURE;
                }
                n = sprintf(enccmd,"openssl enc -d -aes-256-cbc -salt -in %s -out %s -pass pass:%s","/tmp/icmpstegano.enc",fname.c_str(),
                            passwd.c_str());                
                cout <<endl<<"Debug Msg: "<<enccmd;
                
                if(system(enccmd))
                    cout<<endl<<"File encryption completed ...";
                else{
                    cerr<<"\n openSSL failed !!! :(";
                    return EXIT_FAILURE;
                }                  
                break;                
        }        
    }
    catch(TCLAP::ArgException &e){
        cerr<<"error: "<<e.error()<<"for arg"<<e.argId()<<endl;
        return EXIT_FAILURE;
    }             
//    unsigned char datarply[] = "\x45\x0\x0\x54\xCE\xEF\x0\x0\x40\x1\xAD\xB7\x7F\x0\x0\x1\x7F\x0\x0\x1\x0\x0\x9E\xED\x20\x21\x5\x0\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F\x60\x61\x62\x63\x64\x65\x66\x0";
//    unsigned char datareqst[] = "\x45\x0\x0\x54\x0\x0\x40\x0\xFF\x1\x7D\xA6\x7F\x0\x0\x1\x7F\x0\x0\x1\x8\x0\x96\xED\x20\x21\x5\x0\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F\x60\x61\x62\x63\x64\x65\x66\x0";
//    IcmpStegano *testobj = new IcmpStegano("127.0.0.1",STEGANO_SEND);
//    
//    testobj->SetFname("/testfile.txt");
//    
//    testobj->Icmp_SendFileSize();
//    testobj->SetMode(STEGANO_BURST);
// if(testobj->Icmp_SendFile())
//        std::cout<<"\n File has sent successfully";
//    else
//    {
//        std::cout<<"\n File send failed!!! :(";
//        std::cout<<"\n Packets Sent: "
//                <<testobj->Get_Current_Pkt();
//    }
//   
    
    
//    int length;
//    
//    
//    
//    IcmpStegano *testobj = new IcmpStegano("127.0.0.1",STEGANO_RECV);
//    
//      testobj->SetMode(STEGANO_BURST);
//      testobj->SetFname("/root/testfile.recive.txt");      
//      length = testobj->Icmp_GetFileSize();
//      std::cout<<"\n File size :"
//              <<length;
//      testobj->Icmp_ReceiveFile();


    //    testobj->display(2);

    //testobj->display(datareqst,sizeof(datareqst));
    delete icmpstegano; // Freeing up memory
    std::cout<<endl<<"Program execution finished"<<endl;
    return EXIT_SUCCESS;
}

