#-------------------------------------------------
#
# Project created by QtCreator 2013-03-24T19:44:26
# Description: GUI tool for network steganography tool. This GUI tool also
# includes cryptography and compression support for the tool. This
# program works fine only with super user (su,sudo,gksudo or root).
#
# contact : pshanoop@gmail.com . Please specify subject as ICMPStegano.
#
#-------------------------------------------------

QT       += core gui
QT       += network

TARGET = ICMPStegano_GUI
TEMPLATE = app
#aditional libarary for OpenSSL Support
LIBS = -lssl
LIBS += -lcrypto


SOURCES += main.cpp\
        mainwindow.cpp \
    compress.c \
    crypto.c \
    msgqueue.cpp \
    status_watcher.cpp

HEADERS  += mainwindow.h \
    compress.h \
    crypto.h \
    msgqueue.h \
    status_watcher.h

FORMS    += mainwindow.ui
