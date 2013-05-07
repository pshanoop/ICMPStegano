#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QNetworkInterface>
#include <qmath.h>
#include <QFileDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <QProcess>
#include <QTime>
#include <QDebug>


#include "status_watcher.h"
//#include "msgqueue.h"


//macros for network layer SteganoICMP
#define STEGANO_SEND 3
#define STEGANO_RECV 2
#define STEGANO_BURST 1
#define STEGANO_SECURE 2

//end of macros for network layer SteganoICMP


namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    void  startProcess(QString path,QStringList args);
    ~MainWindow();

private slots:

    void on_rd_secure_clicked();

    void on_txt_passwd_textEdited(const QString &arg1);

    void on_txt_fpath_textChanged(const QString &arg1);

    void on_rd_burst_clicked();

    void on_btn_load_clicked();

    void on_rd_send_clicked();

    void on_rd_recv_clicked();

    void on_btn_setTimeOut_clicked();

    void readyStandardOutput();

    void readyStandardError();

    void on_btn_start_clicked();

    void on_btn_stop_clicked();

    void onProgressed(int i);

    void onFinished(int exit_code);    

    void on_btn_decrypt_clicked();

    void on_btn_new_clicked();

private:
    Ui::MainWindow *ui;
    int no_of_packet; // required to send or recive file
    void securitycalc();
    void post_recv(); // post processes of receive
    QTime Ntimer;// Timer for network layer process
    QString pathprefix; // pathprefix for all temporary files

    QProcess *coreprocess; // process pointer
    msgqueue msg_stop; // IPC msg stop pointer
    Status_Watcher *stat_watcher; // thread to accept status report from child process

    int cmode; // communication mode
    int mode;   // steganography mode
    int timeout; // time out for receive process

    int startflag; // process start flag
};

#endif // MAINWINDOW_H
