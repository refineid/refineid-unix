# Makefile for RefineID Konqueror mTLS Bridge components on FreeBSD
CXX ?= c++
PREFIX ?= /usr/local
CADIR ?= $(DESTDIR)$(PREFIX)/etc/refineid/ca
CERTSDIR ?= $(DESTDIR)$(PREFIX)/share/certs

OPENSSL_INCS ?= -I$(PREFIX)/include
OPENSSL_LIBS ?= -L$(PREFIX)/lib -lssl -lcrypto -lpthread

QT6_INCS ?= -I$(PREFIX)/include/qt6 -I$(PREFIX)/include/qt6/QtCore -I$(PREFIX)/include/qt6/QtWidgets -I$(PREFIX)/include/qt6/QtGui
QT6_LIBS ?= -L$(PREFIX)/lib/qt6 -lQt6Core -lQt6Gui -lQt6Widgets

all: refineid-mtls-proxy refineid-ask-pin

refineid-mtls-proxy: refineid_mtls_proxy.cpp
	$(CXX) -O2 $(OPENSSL_INCS) $(OPENSSL_LIBS) refineid_mtls_proxy.cpp -o refineid-mtls-proxy

refineid-ask-pin: refineid_ask_pin.cpp
	$(CXX) -O2 -fPIC $(QT6_INCS) $(QT6_LIBS) refineid_ask_pin.cpp -o refineid-ask-pin

ca:
	install -d $(CADIR)
	@if [ ! -f $(CADIR)/ca.key ]; then \
		echo "Generating RefineID Local Bridge CA..."; \
		openssl req -x509 -new -newkey rsa:4096 -nodes \
			-keyout $(CADIR)/ca.key -out $(CADIR)/ca.crt -days 3650 \
			-subj "/CN=RefineID Local Bridge CA/O=RefineID/C=FI"; \
		chmod 600 $(CADIR)/ca.key; \
	fi
	@if [ ! -f $(CADIR)/server.key ]; then \
		echo "Generating server key and certificate..."; \
		openssl genrsa -out $(CADIR)/server.key 2048; \
		openssl req -new -key $(CADIR)/server.key -out $(CADIR)/server.csr -config cert.cnf; \
		openssl x509 -req -in $(CADIR)/server.csr -CA $(CADIR)/ca.crt -CAkey $(CADIR)/ca.key \
			-CAcreateserial -out $(CADIR)/server.crt -days 3650 -extfile cert.cnf -extensions v3_req; \
		chmod 644 $(CADIR)/server.key; \
	fi
	@if [ -d $(CERTSDIR) ]; then \
		echo "Installing CA to $(CERTSDIR)/refineid-ca.pem..."; \
		cp $(CADIR)/ca.crt $(CERTSDIR)/refineid-ca.pem; \
		if command -v certctl >/dev/null 2>&1; then certctl rehash; fi; \
	fi

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
