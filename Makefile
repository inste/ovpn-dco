.PHONY: all version distclean clean

ifneq ($(KERNELRELEASE),)

NOSTDINC_FLAGS += -I$(SUBDIRS)/include/

ccflags-y += -DDEBUG=1

obj-m			:= ovpn-dco.o
ovpn-dco-y		+= drivers/net/ovpn-dco/main.o
ovpn-dco-y		+= drivers/net/ovpn-dco/bind.o
ovpn-dco-y		+= drivers/net/ovpn-dco/crypto.o
ovpn-dco-y		+= drivers/net/ovpn-dco/ovpn.o
ovpn-dco-y		+= drivers/net/ovpn-dco/peer.o
ovpn-dco-y		+= drivers/net/ovpn-dco/sock.o
ovpn-dco-y		+= drivers/net/ovpn-dco/stats.o
ovpn-dco-y		+= drivers/net/ovpn-dco/netlink.o
ovpn-dco-y		+= drivers/net/ovpn-dco/crypto_none.o
ovpn-dco-y		+= drivers/net/ovpn-dco/crypto_aead.o
ovpn-dco-y		+= drivers/net/ovpn-dco/pktid.o
ovpn-dco-y		+= drivers/net/ovpn-dco/tcp.o
ovpn-dco-y		+= drivers/net/ovpn-dco/udp.o
ovpn-dco-y		+= drivers/net/ovpn-dco/fragment.o

else

PWD		:= $(shell pwd)
KERNELDIR	?= /lib/modules/$(shell uname -r)/build
VERSION_FILE	:= ovpn-dco_version.h
VERSION		:= $(shell git describe --tag | sed -e 's/-g/-/')
SAVED_VERSION	:= \
	$(shell sed -e 's/.*"\(.*\)".*/\1/p;d' $(VERSION_FILE) 2> /dev/null)

all: version
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

.PHONY: $(if $(filter $(VERSION),$(SAVED_VERSION)),,$(VERSION_FILE))

version: $(VERSION_FILE)

$(VERSION_FILE):
	@echo "#ifndef __DCO_VERSION_H__"             > $(VERSION_FILE)
	@echo "#define __DCO_VERSION_H__"            >> $(VERSION_FILE)
	@echo "#define DCO_VERSION \""$(VERSION)"\"" >> $(VERSION_FILE)
	@echo "#endif /* __DCO_VERSION_H__ */"       >> $(VERSION_FILE)
	@echo ""                                     >> $(VERSION_FILE)

distclean: clean

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	@rm -f $(VERSION_FILE)

endif
