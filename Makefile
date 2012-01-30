
.PHONY : default
default:
	@echo To install TACKpy run \"setup.py install\"

VERSION := 0.9.2
SCDIR := selfcontained

# Variables for testing
TESTDIR = test
PYTHON = python
EXEC = TACK.py
CERT1 = ~/godaddy/gd1.pem
CERT2 = ~/godaddy/gd2.der

.PHONY : clean
clean:
	rm -f src/*.pyc
	rm -rf $(SCDIR)
	rm -rf $(TESTDIR)
	rm -rf build
	rm -rf dist

.PHONY: selfcontained
selfcontained:
	rm -rf $(SCDIR)
	mkdir $(SCDIR)
	./make_selfcontained.py > $(SCDIR)/TACK.py
	chmod +x $(SCDIR)/TACK.py

dist:
	./setup.py sdist

.PHONY: test
test:
	rm -rf $(TESTDIR)
	mkdir $(TESTDIR)
	$(EXEC) test
	# NOTE: USE 'asdf' for passwords...
	$(EXEC) genkey > $(TESTDIR)/TACK_Key1.pem 
	$(EXEC) genkey -p asdf > $(TESTDIR)/TACK_Key2.pem 
	$(EXEC) genkey -p asdf -o $(TESTDIR)/TACK_Key3.pem 
	$(EXEC) create -k $(TESTDIR)/TACK_Key1.pem -c $(CERT1) > $(TESTDIR)/TACK1.pem	
	$(EXEC) c -k $(TESTDIR)/TACK_Key1.pem -p asdf -c $(CERT2) -o $(TESTDIR)/TACK2.pem		
	$(EXEC) c -k $(TESTDIR)/TACK_Key1.pem -p asdf -s v1_key -c $(CERT1) -o $(TESTDIR)/TACK3.pem			
	$(EXEC) c -k $(TESTDIR)/TACK_Key1.pem -p asdf -s v1_cert -d 30d -c $(CERT1) -o $(TESTDIR)/TACK4.pem			
	$(EXEC) c -k $(TESTDIR)/TACK_Key1.pem -p asdf -s v1_key -d 1d12h5m -e 2030-06-06Z -c $(CERT1) -o $(TESTDIR)/TACK5.pem
	$(EXEC) c -k $(TESTDIR)/TACK_Key1.pem -p asdf -s v1_key -g 1 -c $(CERT1) -o $(TESTDIR)/TACK6.pem
	$(EXEC) update -k $(TESTDIR)/TACK_Key1.pem -c $(CERT1) -i $(TESTDIR)/TACK1.pem > $(TESTDIR)/TACK1_1.pem	
	$(EXEC) up -k $(TESTDIR)/TACK_Key1.pem -p asdf -c $(CERT2) -i $(TESTDIR)/TACK2.pem -o $(TESTDIR)/TACK2_1.pem		
	$(EXEC) u -k $(TESTDIR)/TACK_Key1.pem -p asdf -s v1_key -c $(CERT1) -i $(TESTDIR)/TACK3.pem -o $(TESTDIR)/TACK3_1.pem			
	$(EXEC) u -k $(TESTDIR)/TACK_Key1.pem -p asdf -s v1_cert -d 30d -g 2 -c $(CERT1) -i $(TESTDIR)/TACK4.pem -o $(TESTDIR)/TACK4_1.pem			
	$(EXEC) u -k $(TESTDIR)/TACK_Key1.pem -p asdf -s v1_key -d 1d12h5m -e 2030-06-06Z -c $(CERT1) -i $(TESTDIR)/TACK5.pem -o $(TESTDIR)/TACK5_1.pem	
	$(EXEC) u -k $(TESTDIR)/TACK_Key1.pem -p asdf -s v1_key -g 255 -c $(CERT1) -i $(TESTDIR)/TACK6.pem -o $(TESTDIR)/TACK6_1.pem
	$(EXEC) adjust -i $(TESTDIR)/TACK1_1.pem -d 8h30m > $(TESTDIR)/TACK1_2.pem
	$(EXEC) a -i $(TESTDIR)/TACK2_1.pem -d 1095d1m -o $(TESTDIR)/TACK2_2.pem
	$(EXEC) break -k $(TESTDIR)/TACK_Key1.pem -p asdf -i $(TESTDIR)/TACK5.pem > $(TESTDIR)/TACK_Break_Sig5_1.pem
	$(EXEC) b -k $(TESTDIR)/TACK_Key1.pem -p asdf -i $(TESTDIR)/TACK5.pem -o $(TESTDIR)/TACK_Break_Sig5_2.pem
	$(EXEC) view $(TESTDIR)/TACK_Key1.pem > $(TESTDIR)/TACK_View_Key1.txt
	$(EXEC) view $(TESTDIR)/TACK1.pem > $(TESTDIR)/TACK_View1.txt
	$(EXEC) v $(TESTDIR)/TACK_Break_Sig5_1.pem > $(TESTDIR)/TACK_View_Break_Sig5_1.txt
	$(EXEC) v $(CERT1) > $(TESTDIR)/TACK_View_Cert1.txt
	$(EXEC) v $(CERT2) > $(TESTDIR)/TACK_View_Cert2.txt
	@echo OK
