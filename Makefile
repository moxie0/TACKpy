
TESTDIR = testoutput

.PHONY : default
default:
	@echo To install tackpy run \"./setup.py install\" or \"make install\"
	@echo

.PHONY: install
install:
	./setup.py install

.PHONY : clean
clean:
	rm -f `find . -name *.pyc`
	rm -rf build
	rm -rf $(TESTDIR)

# Variables for testing
TESTDIR = testoutput
EXEC = ./tack.py
CERT1 = ./testdata/serverX509Cert.pem
CERT2 = ./testdata/serverX509Cert.der

.PHONY: test
test:
	rm -rf $(TESTDIR)
	mkdir $(TESTDIR)
	#$(EXEC) test
	# NOTE: USE 'asdf' for passwords...
	$(EXEC) genkey > $(TESTDIR)/TACK_Key1.pem 
	$(EXEC) genkey -p asdf > $(TESTDIR)/TACK_Key2.pem 
	$(EXEC) genkey -p asdf -o $(TESTDIR)/TACK_Key3.pem 
	$(EXEC) sign -k $(TESTDIR)/TACK_Key1.pem -c $(CERT1) > $(TESTDIR)/TACK1.pem	
	$(EXEC) sign -k $(TESTDIR)/TACK_Key1.pem -p asdf -c $(CERT2) -o $(TESTDIR)/TACK2.pem		
	$(EXEC) sign -k $(TESTDIR)/TACK_Key1.pem -p asdf -c $(CERT1) -m2 -o $(TESTDIR)/TACK3.pem			
	$(EXEC) sign -k $(TESTDIR)/TACK_Key1.pem -p asdf -c $(CERT1) -o $(TESTDIR)/TACK4.pem			
	$(EXEC) sign -k $(TESTDIR)/TACK_Key1.pem -p asdf -e 2030-06-06Z -c $(CERT1) -o $(TESTDIR)/TACK5.pem
	$(EXEC) sign -k $(TESTDIR)/TACK_Key1.pem -p asdf -g2 -m2 -c $(CERT1) -o $(TESTDIR)/TACK6.pem
	$(EXEC) sign -k $(TESTDIR)/TACK_Key1.pem -p asdf -m250 -g251 -c $(CERT1) -o $(TESTDIR)/T6 -e 2013-01-02Z -n 3@1d
	$(EXEC) break -k $(TESTDIR)/TACK_Key1.pem -p asdf > $(TESTDIR)/TACK_Break_Sig1.pem
	$(EXEC) b -k $(TESTDIR)/TACK_Key2.pem -p asdf -o $(TESTDIR)/TACK_Break_Sig2.pem
	cat $(TESTDIR)/TACK_Break_Sig1.pem $(TESTDIR)/TACK_Break_Sig2.pem > $(TESTDIR)/TACK_Break_Sigs.pem
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
