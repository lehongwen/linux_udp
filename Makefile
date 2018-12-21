export EXAMPLE_DIR=$(shell pwd)
export OUT_DIR=$(EXAMPLE_DIR)/../../out/x86_eTC

#OFP_LIBS += -lpthread -ldl -lrt -lm
OFP_LIBS += -pthread -ldl -lrt -lm

OFP_CFLAGS += -g -rdynamic
OFP_CFLAGS += -Wall
OFP_CFLAGS += -W
OFP_CFLAGS += -O2
OFP_CFLAGS += -m32
OFP_CFLAGS += -pthread

OFPK_CC      = gcc

CFLAGS += $(OFP_CFLAGS)
CFLAGS += $(OFP_IFLAGS)

LIBS += $(OFP_LLIBS)
LIBS += $(OFP_LIBS)

ODIR = obj
TARGETS=linux_udp

_DEPS = linux_udp.h
_OBJ  = linux_udp.o linux_udp_server.o linux_udp_client.o

%.o: %.c $(_DEPS)
	$(OFPK_CC) -c -o $@ $< $(CFLAGS)
	
$(TARGETS): $(_OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)
	cp $(TARGETS) $(OUT_DIR)/bin/
	
.PHONY: clean

clean:
	rm -f *.o
	rm -f $(TARGETS) 
	rm $(OUT_DIR)/bin/$(TARGETS) 
