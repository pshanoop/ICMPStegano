#include <QtGui/QApplication>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.setWindowTitle("SteganoICMP");
    w.show();



    return a.exec();
}


/*
    int ret; // application return flag
    QPointer<QApplication> a;
    QPointer<MainWindow> w;
    do{
        if(a) delete a; // deletes old memmory in next itr
        if(w) delete w; // deletes old memmory in next itr
        a= new QApplication(argc, argv);
        w=new MainWindow();
        w->setWindowTitle("ICMPStegano");
        w->show();
        ret = a->exec();
    } while( ret == RESTART_CODE);
    return ret;
  */
