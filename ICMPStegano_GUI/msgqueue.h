/* 
 * File:   msgqueue.h
 * Author: root
 *
 * Created on April 13, 2013, 9:19 PM
 */
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <ctype.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define MAX_SEND_SIZE 80

struct qmsgbuf {
        long mtype;
        char mtext[MAX_SEND_SIZE];
};

#ifndef MSGQUEUE_H
#define	MSGQUEUE_H



class msgqueue {
public:
    msgqueue();
    msgqueue(int qid);
    msgqueue(const msgqueue& orig);
    
    void send_message(long type,char *msg);
    void read_message(int type, char *buf);
    int getqid();
    
    
    virtual ~msgqueue();
private:
    int qid;
    struct qmsgbuf *qbuf;
    key_t key;    

};

#endif	/* MSGQUEUE_H */

