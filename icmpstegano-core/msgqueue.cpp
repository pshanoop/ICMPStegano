/* 
 * File:   msgqueue.cpp
 * Author: root
 * 
 * Created on April 13, 2013, 9:19 PM
 */

#include <string.h>

#include "msgqueue.h"


msgqueue::msgqueue() {
    std::cout<<"\nQueue created !!!";
    key = ftok(".",'m');
    qbuf = new qmsgbuf;
    if((qid = msgget(key, IPC_CREAT|0660)) == -1) {
                std::cerr<<"\nmsgget";
                exit(EXIT_FAILURE);
     }
        
}
msgqueue::msgqueue(int qid){
    std::cout<<"\nQueue created !!!";
    this->qid = qid;
    qbuf = new qmsgbuf;
}

int msgqueue::getqid(){
    return this->qid;
}

void msgqueue::send_message(long type, char* msg){
    std::cout<<"\nSending message !!!";
    qbuf->mtype = type;
    memcpy(qbuf->mtext,msg,MAX_SEND_SIZE);
    if((msgsnd(qid,(struct qmsgbuf *)qbuf,MAX_SEND_SIZE,0)) == -1){
        perror("Msg Send Error: ");
        exit(EXIT_FAILURE);
    }
}

void msgqueue::read_message(int type, char* buf){
    std::cout<<"\nReading IPC message !!!";
    qbuf->mtype = type;
    if((msgrcv(qid,(struct msgbuf *)qbuf,MAX_SEND_SIZE,type,0))== -1)
        perror("msgrcv failed ");
    else{
        printf("\nIPC Type: %ld Text: %s \n", qbuf->mtype, qbuf->mtext);    
        memcpy(buf,qbuf->mtext,MAX_SEND_SIZE);
    }
}
msgqueue::msgqueue(const msgqueue& orig) {
}

msgqueue::~msgqueue() {
   // msgctl(qid, IPC_RMID, 0);
    delete qbuf; 
    std::cout<<"\nqueue removed\n";
    
}

