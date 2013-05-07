#ifndef STATUS_WATCHER_H
#define STATUS_WATCHER_H

#include <QThread>
#include <QDebug>
#include "msgqueue.h"

class Status_Watcher : public QThread
{
    Q_OBJECT
public:
    explicit Status_Watcher(QObject *parent = 0);
    void run();
    long getqid_stat();
    ~Status_Watcher();
signals:
     void Progressed (int i); // status changed i is perctl of progrss
private:
     msgqueue *msg_stat;
};

#endif // STATUS_WATCHER_H
