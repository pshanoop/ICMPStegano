/* 
 * File:   IcmpStegano_new.cpp
 * Ver : 0.2
 * Author: Shanoop Pattanath
 * Description: This is the main cpp file for ICMPStegano-core. This creates a
 *  command line interface for ICMPStegano-core. This program only sends/receives 
 *  file which specified through the cmdline option fnameArg to the specified system
 *  cmdline option ipArg. The packets are send asynchronously. So pause and resume
 *  options are not available. We may add this in feature versions.
 *              The program can be controlled by the parent process using 
 *  IPC:Message Queues In and Out, the queue id must be specified in cmdline using 
 *  options -O/-Out and -I/-In. The In message queue used to stop communication 
 *  and exit the program. By sending msg type 999 with string stop. The Out msg 
 *  queue is used to give status report for the parent process through msg type 
 *  777 and progress as string number(0-100).
 *  
 * Notes:- 
 *  1) This program not intend to work independently. 
 *  2) This program is completely depend on ICMPStegano-GUI. 
 *  3) Data send through this program is not encrypted.
 *  4) Encryption and compression is done by depend program ICMPStegano-GUI. 
 *  5) Both program should be run by root or sudo user only.
 *  6) This program not tested on Big-Endian Architecture.
 * 
 * Compiler Notes:-
 *  1) Should be compiled using g++ command
 *  2) add options -pthread . Because IcmpStegano.h is a multi-thread code
 * 
 * License Notice:-
 *   
 */

#include <iostream>
#include "IcmpStegano.h" 
#include <tclap/CmdLine.h> // command line parser
#include <string>

using namespace std;

int main(int argc, char** argv) {
      
    IcmpStegano *icmpstegano;
    int cmode =0;  // communication mode
    int ret_flag=EXIT_SUCCESS;       
    try{
        TCLAP::CmdLine cmd("Command Line description Message",' ',"1.1 Unstable");                
        TCLAP::ValueArg<string> fnameArg("f","file","File to Send/Receive",true,"/tmp/test","string");  // Change requred on defualt value
        TCLAP::ValueArg<string> ipArg("i","ip","IPv4 of Sender/Receiver",true,"127.0.0.1","string"); // Change requred on defualt value
        TCLAP::ValueArg<int> timeoutArg("t","timeOut","Time Out for receiver in milliseconds",false,800,"Integer"); // TODO
        TCLAP::ValueArg<long> IPCArg_in("I","In","Message queue id for IPC _int",true,-1,"Integer => 0");
        TCLAP::ValueArg<long> IPCArg_out("O","Out","Message queue id for IPC _out",true,-1,"Integer => ");
        
        vector<string> allowed;
        allowed.push_back("secure");
        allowed.push_back("burst");
        
        TCLAP::ValuesConstraint<string> allowedVals(allowed);
        TCLAP::ValueArg<string> modeArg("m","mode","Steganography mode secure or burst. "
                                        "Burst is faster but less secure and secure is slower but more secure",true,"secure",&allowedVals);
        cmd.add(modeArg);        
        cmd.add(fnameArg);
        cmd.add(ipArg);       
        cmd.add(timeoutArg);
        cmd.add(IPCArg_in);
        cmd.add(IPCArg_out);
        
        TCLAP::SwitchArg sendArg("s","send","Communication mode send or receive",true);        
        TCLAP::SwitchArg recvArg("r","receive","Communication mode send or receive",true);
        cmd.xorAdd(sendArg,recvArg);

        
        cmd.parse( argc, argv ); // parsing the arguments
        
        string fname = fnameArg.getValue();
        string ip = ipArg.getValue();        
        int timeout = timeoutArg.getValue(); // TODO time out
        long ipc_in= IPCArg_in.getValue();
        long ipc_out=IPCArg_out.getValue();
        string mode = modeArg.getValue();        
                       
        if(sendArg.isSet())
            cmode =STEGANO_SEND;
        else if(recvArg.isSet())
            cmode =STEGANO_RECV;
//        cout<<"\n Command line specified"
//                <<"\n File: "<<fname
//                <<"\n Ip: "<<ip
//               // <<"\n password: "<<passwd
//                <<"\n time Out: "<<timeout
//                <<"\n Fifo: "<<pipe
//                <<"\n mode: "<<mode                
//                <<"\n cmode: "<<cmode //2= receive, 3 = send
//                <<"\n IPC_in: "<<ipc_in
//                <<"\n IPC_out: "<<ipc_out<<endl;                       
        switch(cmode){
            case STEGANO_SEND: 
                icmpstegano = new IcmpStegano(ip.c_str(),STEGANO_SEND);
                icmpstegano->SetFname(fname.c_str());  // change fname                
                icmpstegano->SetQid(ipc_in,ipc_out); // Creates message queues                
                if(icmpstegano->Icmp_SendFileSize())
                {
                    if(mode == "secure")
                      icmpstegano->SetMode(STEGANO_SECURE);
                    else if(mode == "burst")
                      icmpstegano->SetMode(STEGANO_BURST);                      
                     if(icmpstegano->Icmp_SendFile() == 1)
                        std::cout<<"\n File has sent successfully :)";
                     else{                     
                        std::cerr<<"\n File send failed or stoped!!! :(";
                        std::cerr<<"\n Packets Sent: "
                                <<icmpstegano->Get_Current_Pkt();
                     }                    
                }
                else{                    
                    cerr<<"Fine size send failed or stoped !!! :(";
                    ret_flag = EXIT_FAILURE; // changed here
                    goto cleanup;
                }                                                    
                break;
            case STEGANO_RECV:
                
                icmpstegano = new IcmpStegano(ip.c_str(),STEGANO_RECV);
                icmpstegano->SetFname(fname.c_str()); // changed fname
                icmpstegano->SetQid(ipc_in,ipc_out); // Creates message queues                
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
                    cerr<<"Fine size Receive failed !!! :(";
                     ret_flag = EXIT_FAILURE; // changed here
                    goto cleanup;
                }    
                break;                
        }        
    }
    catch(TCLAP::ArgException &e){
        cerr<<"error: "<<e.error()<<"for arg"<<e.argId()<<endl;
        return EXIT_FAILURE;
    }             

    /*
     * cmdline ver 1.1 tests
     * -m secure -i 172.18.15.88 -r -I  0 -O  0 -f /tmp/ICMP_stegano_temp.z.enc 
     * -m secure -i 172.18.15.88 -s -I  1048576 -O  1048576 -f /tmp/ICMP_stegano_temp.z.enc
     */
    cleanup:
        delete icmpstegano; // Freeing up memory
        std::cout<<endl<<"Program execution finished"<<((ret_flag ==0)? " successfully":" with something horrible wrong :( !!")<<endl;        
        return ret_flag;
}