keys:
	# delete old keys
	rm -f rsa2k*
	# Make a CA
	ssh-keygen -q -t rsa -b 2048 -f rsa2kCA -C "rsa2kCA" -P ""
	# Make a server key
	ssh-keygen -q -t rsa -b 2048 -f rsa2k -C "test key rsa2k" -P ""
	# sign the key
	ssh-keygen -s rsa2kCA -I user -n ${USER} rsa2k.pub
	# give a OK name
	# mv rsa2k-cert.pub rsa2k-rsa2k-cert.pub
	# cp ~/.ssh/id_rsa.pub authorized_keys
