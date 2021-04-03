all: clean
	gcc -Wall -o t-decrypt-verify t-decrypt-verify.c `gpgme-config --cflags --libs`
	gcc -Wall -o t-decrypt t-decrypt.c `gpgme-config --cflags --libs`
	gcc -Wall -o t-encrypt-large t-encrypt-large.c `gpgme-config --cflags --libs`
	gcc -Wall -o t-encrypt-sign t-encrypt-sign.c `gpgme-config --cflags --libs`
	gcc -Wall -o t-encrypt t-encrypt.c `gpgme-config --cflags --libs`
	gcc -Wall -o t-engine-info t-engine-info.c `gpgme-config --cflags --libs`
	gcc -Wall -o t-export t-export.c `gpgme-config --cflags --libs`
	gcc -Wall -o t-genkey t-genkey.c `gpgme-config --cflags --libs`
	gcc -Wall -o t-gpg t-gpg.c `gpgme-config --cflags --libs`
	gcc -Wall -o t-sign t-sign.c `gpgme-config --cflags --libs`

clean:
	-rm t-decrypt-verify t-decrypt t-encrypt-large t-encrypt-sign t-encrypt t-engine-info t-export t-genkey t-gpg t-sign