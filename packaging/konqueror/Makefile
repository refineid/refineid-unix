# Makefile for RefineID Konqueror mTLS Bridge components on FreeBSD
CXX ?= c++
PREFIX ?= /usr/local

OPENSSL_INCS ?= -I$(PREFIX)/include
OPENSSL_LIBS ?= -L$(PREFIX)/lib -lssl -lcrypto -lpthread

QT6_INCS ?= -I$(PREFIX)/include/qt6 -I$(PREFIX)/include/qt6/QtCore -I$(PREFIX)/include/qt6/QtWidgets -I$(PREFIX)/include/qt6/QtGui
QT6_LIBS ?= -L$(PREFIX)/lib/qt6 -lQt6Core -lQt6Gui -lQt6Widgets

all: refineid-mtls-proxy refineid-ask-pin

refineid-mtls-proxy: refineid_mtls_proxy.cpp
	$(CXX) -O2 $(OPENSSL_INCS) $(OPENSSL_LIBS) refineid_mtls_proxy.cpp -o refineid-mtls-proxy

refineid-ask-pin: refineid_ask_pin.cpp
	$(CXX) -O2 -fPIC $(QT6_INCS) $(QT6_LIBS) refineid_ask_pin.cpp -o refineid-ask-pin

install: all
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 refineid-mtls-proxy $(DESTDIR)$(PREFIX)/bin/
	install -m 755 refineid-ask-pin $(DESTDIR)$(PREFIX)/bin/
	install -d $(DESTDIR)$(PREFIX)/etc/refineid
	install -m 644 openssl_pkcs11.cnf $(DESTDIR)$(PREFIX)/etc/refineid/
	install -d $(DESTDIR)$(PREFIX)/etc/xdg/autostart
	install -m 644 refineid-mtls-proxy.desktop $(DESTDIR)$(PREFIX)/etc/xdg/autostart/

clean:
	rm -f refineid-mtls-proxy refineid-ask-pin
