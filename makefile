GPGMECONFIG=`gpgme-config --cflags --libs`
CC=gcc
CCFLAGS=-Wall -O3
INC=./

all: clean
	@echo "================================================================="
	$(CC) $(CCFLAGS) -o t-decrypt-verify t-decrypt-verify.c -I$(INC) $(GPGMECONFIG)
	@echo "================================================================="
	$(CC) $(CCFLAGS) -o t-decrypt t-decrypt.c -I$(INC) $(GPGMECONFIG)
	@echo "================================================================="
	$(CC) $(CCFLAGS) -o t-encrypt-large t-encrypt-large.c -I$(INC) $(GPGMECONFIG)
	@echo "================================================================="
	$(CC) $(CCFLAGS) -o t-encrypt-sign t-encrypt-sign.c -I$(INC) $(GPGMECONFIG)
	@echo "================================================================="
	$(CC) $(CCFLAGS) -o t-encrypt t-encrypt.c -I$(INC) $(GPGMECONFIG)
	@echo "================================================================="
	$(CC) $(CCFLAGS) -o t-engine-info t-engine-info.c -I$(INC) $(GPGMECONFIG)
	@echo "================================================================="
	$(CC) $(CCFLAGS) -o t-export t-export.c -I$(INC) $(GPGMECONFIG)
	@echo "================================================================="
	$(CC) $(CCFLAGS) -o t-genkey t-genkey.c -I$(INC) $(GPGMECONFIG)
	@echo "================================================================="
	$(CC) $(CCFLAGS) -o t-gpg t-gpg.c -I$(INC) $(GPGMECONFIG)
	@echo "================================================================="
	$(CC) $(CCFLAGS) -o t-sign t-sign.c -I$(INC) $(GPGMECONFIG)

clean:
	-rm t-decrypt-verify t-decrypt t-encrypt-large t-encrypt-sign t-encrypt t-engine-info t-export t-genkey t-gpg t-sign