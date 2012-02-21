
.PHONY : default
default:
	@echo To install TACKpy run \"./setup.py install\" or \"make install\"

SCDIR := selfcontained

# Variables for testing
TESTDIR = testoutput
EXEC = TACK.py
CERT1 = ./testdata/serverX509Cert.pem
CERT2 = ./testdata/serverX509Cert.der

.PHONY: install
install:
	./setup.py install

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

dist: selfcontained
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
	$(EXEC) sign -k $(TESTDIR)/TACK_Key1.pem -c $(CERT1) -d5m > $(TESTDIR)/TACK1.pem	
	$(EXEC) sign -k $(TESTDIR)/TACK_Key1.pem -p asdf -c $(CERT2) -d5m -o $(TESTDIR)/TACK2.pem		
	$(EXEC) sign -k $(TESTDIR)/TACK_Key1.pem -p asdf -c $(CERT1) -m2 -d30d -o $(TESTDIR)/TACK3.pem			
	$(EXEC) sign -k $(TESTDIR)/TACK_Key1.pem -p asdf -d 30d -c $(CERT1) -o $(TESTDIR)/TACK4.pem			
	$(EXEC) sign -k $(TESTDIR)/TACK_Key1.pem -p asdf -d 1d12h5m -e 2030-06-06Z -c $(CERT1) -o $(TESTDIR)/TACK5.pem
	$(EXEC) sign -k $(TESTDIR)/TACK_Key1.pem -p asdf -g2 -m2 -c $(CERT1) -d8h30m -o $(TESTDIR)/TACK6.pem
	$(EXEC) sign -k $(TESTDIR)/TACK_Key1.pem -p asdf -m250 -g251 -c $(CERT1) -d24h -o $(TESTDIR)/T6 -e 2013-01-02Z -n 3@1d
	$(EXEC) break -k $(TESTDIR)/TACK_Key1.pem -p asdf -i $(TESTDIR)/TACK5.pem > $(TESTDIR)/TACK_Break_Sig5.pem
	$(EXEC) b -k $(TESTDIR)/TACK_Key1.pem -p asdf -i $(TESTDIR)/TACK6.pem -o $(TESTDIR)/TACK_Break_Sig6.pem
	cat $(TESTDIR)/TACK_Break_Sig5.pem $(TESTDIR)/TACK_Break_Sig6.pem > $(TESTDIR)/TACK_Break_Sigs.pem
	$(EXEC) tackcert -i $(TESTDIR)/TACK3.pem > $(TESTDIR)/TACK_Cert3.pem
	$(EXEC) tackcert -i $(TESTDIR)/TACK4.pem -b $(TESTDIR)/TACK_Break_Sigs.pem > $(TESTDIR)/TACK_Cert4.pem
	$(EXEC) tackcert -i $(TESTDIR)/TACK_Cert3.pem > $(TESTDIR)/TACK3_FromCert.pem
	$(EXEC) view $(TESTDIR)/TACK_Key1.pem > $(TESTDIR)/TACK_View_Key1.txt
	$(EXEC) view $(TESTDIR)/TACK1.pem > $(TESTDIR)/TACK_View1.txt
	$(EXEC) v $(TESTDIR)/TACK_Break_Sigs.pem > $(TESTDIR)/TACK_View_Break_Sigs.txt
	$(EXEC) v $(CERT1) > $(TESTDIR)/TACK_View_Cert1.txt
	$(EXEC) v $(CERT2) > $(TESTDIR)/TACK_View_Cert2.txt
	$(EXEC) v $(TESTDIR)/TACK_Cert3.pem > $(TESTDIR)/TACK_View_TACK_Cert3.txt 
	@echo OK
