#include "status_watcher.h"

Status_Watcher::Status_Watcher(QObject *parent) :
    QThread(parent)
{
    this->msg_stat = new msgqueue;

}
Status_Watcher::~Status_Watcher(){
    delete msg_stat;   // removes queue from system .. can lead core-network-layer crash
}

long Status_Watcher::getqid_stat(){
    return this->msg_stat->getqid();
}

void Status_Watcher::run(){

    int i = 0;
    qDebug()<<"Qid(run): "<<msg_stat->getqid();
    char buf[MAX_SEND_SIZE];
    while(i!=100){
        qDebug()<<"Thread Waiting for status message";
        msg_stat->read_message(777,buf);
        qDebug()<<"Message recieved: "<<buf;
        i = atoi(buf);
        qDebug()<<"Value: "<<i;
        if(i==-1) break; // Thread stops
        emit Progressed(i);
    }
}
