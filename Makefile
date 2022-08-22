sign:
	echo Making a key for the pod and signing it with the private key CA
	rm -f rsa2k*
	# Make a server key
	ssh-keygen -q -t rsa -b 2048 -f rsa2k -C "test key rsa2k" -P ""
	# sign the key
	ssh-keygen -q -s CA -I user -n ${USER} rsa2k.pub
standalone:
	# delete old keys
	rm -f rsa2k*
	# Make a CA
	ssh-keygen -q -t rsa -b 2048 -f rsa2kCA -C "rsa2kCA" -P ""
	# Make a server key
	ssh-keygen -q -t rsa -b 2048 -f rsa2k -C "test key rsa2k" -P ""
	# sign the key
	ssh-keygen -q -s rsa2kCA -I user -n ${USER} rsa2k.pub
	echo "Cert generated for principal ${USER}"
clean:
	rm -f rsa2k*