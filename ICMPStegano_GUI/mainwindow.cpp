#include "mainwindow.h"
#include "ui_mainwindow.h"



#include <cstdio>

extern "C"{
#include "compress.h"
#include "crypto.h"
}


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    //Loading all interface's ipv4 addresses
    foreach (const QHostAddress &address, QNetworkInterface::allAddresses()) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol && address != QHostAddress(QHostAddress::LocalHost))
             ui->cbo_sysip->addItem ( address.toString());

    }
    //creating thread object
    this->stat_watcher = new Status_Watcher(this);

    // connecting signal and slot to change to pg_progress values
    connect(stat_watcher,SIGNAL(Progressed(int)),this,SLOT(onProgressed(int)));
    pathprefix = "/tmp/"; // tmp folder for cryto and compression/decomprsn
    on_rd_send_clicked(); // set default option as sender
    on_rd_secure_clicked(); // set default stegno mode as secure
}
void MainWindow::onProgressed(int i){
    qDebug()<<"Progress value "<<i;
    ui->pg_progress->setValue(i); // Changes progress bar
}

// security meter calculations
void MainWindow::securitycalc(){
    int value = 0;    
    double perctge =0;

    int len =ui->txt_passwd->text().length();    
    if(ui->rd_secure->isChecked())
        value +=50; //50% security for the mode secure
    if(len<8){     // change value according to the length of passsword
        perctge = floor((len/8.0)*100.0);
        perctge/=2;      
        value += perctge;
    }
    else
        value += 50;

    if(value>100)
        value =100;
    ui->pg_smeter->setValue(value);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_rd_secure_clicked()
{
    this->securitycalc();
    this->mode = STEGANO_SECURE;
}

void MainWindow::on_txt_passwd_textEdited(const QString &arg1)
{
     this->securitycalc();
}

void MainWindow::on_txt_fpath_textChanged(const QString &arg1)
{
    this->securitycalc();
}

void MainWindow::on_rd_burst_clicked()
{
    this->securitycalc();
    this->mode = STEGANO_BURST;
}

void MainWindow::on_btn_load_clicked()
{
    if(ui->rd_send->isChecked())
        ui->txt_fpath->setText(QFileDialog::getOpenFileName(this,"Load File","/home",tr("Any File (*.*);;Text file (*.txt);;Compressed file (*.zip *.tar *.rar);;Image (*.png *.xpm *.jpg *.tiff)")));
    else if(ui->rd_recv->isChecked())
        ui->txt_fpath->setText(QFileDialog::getSaveFileName(this,"Save File","/home",tr("Any File (*.*);;Text file (*.txt);;Compressed file (*.zip *.tar *.rar);;Image (*.png *.xpm *.jpg *.tiff)")));
}

void MainWindow::on_rd_send_clicked()
{
    ui->btn_load->setText("Load");
    ui->label_4->setText("IPv4 of Receiver:");    
    this->cmode = STEGANO_SEND;   
}

void MainWindow::on_rd_recv_clicked()
{
    ui->btn_load->setText("Save");
    ui->label_4->setText("IPv4 of Sender:");    
    this->cmode = STEGANO_RECV;    
}

void MainWindow::on_btn_setTimeOut_clicked()
{
    this->timeout=QInputDialog::getInt(this,"Set TimeOut","Time Out(ms): ",0,0,1000,10);
}
void MainWindow::startProcess(QString path,QStringList args){
        this->coreprocess = new QProcess(this);

        connect(this->coreprocess,SIGNAL(readyReadStandardOutput()),this,SLOT(readyStandardOutput()));
        connect(this->coreprocess,SIGNAL(readyReadStandardError()),this,SLOT(readyStandardError()));
        connect(this->coreprocess,SIGNAL(finished(int)),this,SLOT(onFinished(int)));
        this->coreprocess->start(path,args);
        Ntimer.start();
        qDebug()<<"Network layer Process Started PID: "<<coreprocess->pid();
}
void MainWindow::post_recv(){
    QString tmp_path;
    QString tmp_path2;
    //convertion of qstring c style char array.
    QString password_c = ui->txt_passwd->text();
    // file path where the user want save received file
    QString file_path =  ui->txt_fpath->text();
    file_path.replace(" ","\\ "); //replace all spaces with charactor escape
    tmp_path = pathprefix + "ICMP_stegano_temp.z.enc";
    tmp_path2 = pathprefix + "ICMP_stegano_temp.z";
    qDebug()<<"Decryption .. ";
    ui->lbl_status->setText("Decrypting data ...");
    ui->txt_verbose->appendPlainText("[+]["+QTime::currentTime().toString()+"] Decrypting(AES_256_CBC) data...");
    if((crypto_file(tmp_path.toLocal8Bit().data(),tmp_path2.toLocal8Bit().data(),(const unsigned char *)password_c.toLocal8Bit().data(),0))<=0){
        qDebug()<<"ERROR: Decryption failed\n";
        ui->txt_verbose->appendPlainText("[-]["+QTime::currentTime().toString()+"] Decryption(AES_256_CBC) failed."
                                         "Please correct the password. And click Resume Decryption to continue.");
        ui->btn_decrypt->setEnabled(true);
        return;
    }
    ui->txt_verbose->appendPlainText("[+]["+QTime::currentTime().toString()+"] Decryption(AES_256_CBC) finished.");
    qDebug()<<"Decompression ..";
    ui->lbl_status->setText("Decompressing data ...");
    ui->txt_verbose->appendPlainText("[+]["+QTime::currentTime().toString()+"] Decompressing(Zlib) data...");
    FILE *input = fopen (tmp_path2.toLocal8Bit().data(),"r");
    if(input == NULL){
        qDebug()<<"file not found !!";
        ui->txt_verbose->appendPlainText("[-]["+QTime::currentTime().toString()+"] Decompression(Zlib) failed."
                                         "Due to data corruption or low disk space");
        return;
    }
    FILE *output= fopen(file_path.toLocal8Bit().data(),"w");
    if(output== NULL){
        qDebug()<<"File can not be created !!";
        return;
    }
    int ret = inf(input, output);
    if (ret != Z_OK){
        zerr(ret);
        return;
    }
    fclose(input);
    fclose(output);
    ui->txt_verbose->appendPlainText("[+]["+QTime::currentTime().toString()+"] Decompression(Zlib) finished.");
    ui->lbl_status->setText("Process finished.");

}

void MainWindow::onFinished(int exit_code){    
    qDebug()<<"Network Layer Finished(exit_code): "<<exit_code;    
    ui->txt_verbose->appendPlainText("[+]["+QTime::currentTime().toString()+"] Network Layer Finished(exit_code): "+QString::number(exit_code));
    int time_elapsed = Ntimer.elapsed(); // time elapsed for network layer
    ui->lbl_status->setText("Time elapsed " + QString::number(time_elapsed)+ "ms");
    if(ui->rd_recv->isChecked())
    {
       post_recv();
    }
}

void MainWindow::readyStandardError(){
   QByteArray processOutput;
   processOutput = this->coreprocess->readAllStandardError();  
   ui->txt_verbose->appendHtml("<pre><font color=red>[-]["+QTime::currentTime().toString()+"]"+QString(processOutput)+"</font></pre>");
   qDebug()<<QString(processOutput);
}

void MainWindow::readyStandardOutput(){
    QByteArray processOutput;
    processOutput = this->coreprocess->readAllStandardOutput();   
    ui->txt_verbose->appendHtml("<pre><font color=yellow>[+]["+QTime::currentTime().toString()+"]"+QString(processOutput)+"</font></pre>");
    qDebug()<<QString(processOutput);
}
void MainWindow::on_btn_start_clicked()
{
    QStringList args;
    QString file_path;
    QString tmp_path;
    QTime time = QTime::currentTime();
    int ret;
    long qidstats = stat_watcher->getqid_stat();  // Gets the qid of status reporter    
    long qidstop = msg_stop.getqid(); // Gets the qid of stop messager.

    if(ui->rd_secure->isChecked()==true)    
        args.append("-m secure");
    else if(ui->rd_burst->isChecked()==true)
        args.append("-m burst");

    if(ui->txt_fpath->text().length() <= 0){
        ui->txt_fpath->setFocus();
        return;
    }

    if(ui->txt_fsysip->text().length() != 3)
            args.append("-i " + ui->txt_fsysip->text());
    else{
        ui->txt_fsysip->setFocus();
        return;
    }

    if(ui->txt_passwd->text().length() == 0){
        ui->txt_passwd->setFocus();
        return;
    }

    if(ui->rd_send->isChecked() == true){

        pathprefix.append("snd_"); // /tmp/snd_
        args.append("-s");
          //convertion of qstring c style char array.
        QString password_c = ui->txt_passwd->text();
        file_path = ui->txt_fpath->text();
        file_path.replace(" ","\\ "); // replacing spaces with char escape
        //compression
        ui->txt_verbose->appendPlainText("[+]["+time.toString()+"]" +"Compression(Zlib) Started");

        tmp_path =pathprefix +"ICMP_stegano_temp.z";
        qDebug()<<"Compression: "<<tmp_path;
        // "/tmp/snd_ICMP_stegano_temp.z"

        FILE *input = fopen(file_path.toLocal8Bit().data(),"r");
        if(input == NULL)
            perror("File Input(Compression):");
        FILE *output= fopen (tmp_path.toLocal8Bit().data(),"w");
        if(output == NULL)
            perror("File Output(Compression):");
        ret = def(input, output, Z_DEFAULT_COMPRESSION);
         if (ret != Z_OK)
                   zerr(ret);
        fclose(input);
        fclose(output);
        time = QTime::currentTime();
        ui->txt_verbose->appendPlainText("[+]["+time.toString()+"]" +"Compression(Zlib) finished.");
        //encryption
        QString tmp_path2;
        tmp_path2 = tmp_path + ".enc";
        time = QTime::currentTime();
        ui->txt_verbose->appendPlainText("[+]["+time.toString()+"]" +"Encryption(AES_256_CBC) Started");
        if((crypto_file(tmp_path.toLocal8Bit().data(),tmp_path2.toLocal8Bit().data(),(unsigned char *)password_c.toLocal8Bit().data(),1))<=0)
                   qDebug()<<"ERROR: Encryption failed\n";
        qDebug()<<"Encryption: "<<tmp_path;
        time = QTime::currentTime();
        ui->txt_verbose->appendPlainText("[+]["+time.toString()+"]" +"Encryption(AES_256_CBC) finished");
        ui->txt_verbose->appendPlainText("[+]["+time.toString()+"]" +"Starting network layer...");
        args.append("-f "+ tmp_path2);
        //"/tmp/snd_ICMP_stegano_temp.z.enc"
    }
    else if(ui->rd_recv->isChecked() == true){
        pathprefix.append("recv_"); // /tmp/recv_
        args.append("-r");
        tmp_path = pathprefix +"ICMP_stegano_temp.z.enc";
        args.append("-f "+ tmp_path);
        time = QTime::currentTime();
        ui->txt_verbose->appendPlainText("[+]["+time.toString()+"]" +"Starting network layer...");
        ui->lbl_status->setText("Waiting for network layer ...");
        //decompression and decryption is done when progress bar reaches 100
    }

    qDebug()<< "Qid_status : "<<qidstats;
    qDebug()<< "Qid_stop : "<<qidstop;
    if(qidstats < 0 || qidstop < 0){
        qDebug()<<"Message queue creation failed !!!";
        return;
    }

    args.append("-I ");
    //long to number conv
    args.append(QString::number(qidstop).toLocal8Bit().data());
    args.append("-O ");
    //long to number conv
    args.append(QString::number(qidstats).toLocal8Bit().data());

    this->startProcess("/icmpsteganocore",args);
    qDebug()<<args.join(" ");
    time = QTime::currentTime();
    ui->txt_verbose->appendPlainText("  [*]["+time.toString()+"]" +" CmdLn_Arg: \" " + args.join(" ") + "\"");
    stat_watcher->start();
    //* -r -f /tmp/file.txt -i 192.168.0.1 -p passworded -m burst -t 600 -o test.fifo               --pass
    ui->btn_start->setEnabled(false); // restart for new file send or recive
    ui->btn_stop->setEnabled(true);
}

void MainWindow::on_btn_stop_clicked()
{

    try{
    qDebug() <<"QID : "<< msg_stop.getqid()<<endl;
    msg_stop.send_message(999,(char *)"stop");
    }
    catch(...){
        qDebug()<<"Queue removed externaly";
    }
}

void MainWindow::on_btn_decrypt_clicked()
{
    post_recv();// Decrypt and decompress
}

void MainWindow::on_btn_new_clicked()
{
    QProcess::startDetached(qApp->arguments()[0], qApp->arguments()); // create new process and quit this program
    QCoreApplication::quit();
}

