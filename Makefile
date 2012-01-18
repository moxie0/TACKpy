
version := 0.9.2
version_insert := sed -e 's/VV.VV.VV/$(version)/g'
dir := TACK-tool-$(version)
TEST = test


clean:
	rm -rf $(dir)
	rm -rf $(TEST)
	rm -f TACK-tool-*.tar.gz

release:
	mkdir $(dir)
	./make_release.py | $(version_insert) > $(dir)/TACK
	chmod +x $(dir)/TACK
	$(version_insert) README > $(dir)/README
	tar czvf $(dir).tar.gz $(dir)

EXEC = src/main2.py
CERT1 = ~/godaddy/gd1.pem
CERT2 = ~/godaddy/gd2.pem

test:
	rm -rf $(TEST)
	mkdir $(TEST)
	# !!! USE 'asdf' for passwords...
	$(EXEC) genkey > $(TEST)/TACK_Key1.pem 
	$(EXEC) genkey -p asdf > $(TEST)/TACK_Key2.pem 
	$(EXEC) genkey -p asdf -o $(TEST)/TACK_Key3.pem 
	$(EXEC) new -k $(TEST)/TACK_Key1.pem -c $(CERT1) > $(TEST)/TACK1.pem	
	$(EXEC) n -k $(TEST)/TACK_Key1.pem -p asdf -c $(CERT2) -o $(TEST)/TACK2.pem		
	$(EXEC) n -k $(TEST)/TACK_Key1.pem -p asdf -s v1_key -c $(CERT1) -o $(TEST)/TACK3.pem			
	$(EXEC) n -k $(TEST)/TACK_Key1.pem -p asdf -s v1_cert -d 30d -c $(CERT1) -o $(TEST)/TACK4.pem			
	$(EXEC) n -k $(TEST)/TACK_Key1.pem -p asdf -s v1_key -d 1d12h5m -e 2030-06-06Z -c $(CERT1) -o $(TEST)/TACK5.pem
	$(EXEC) n -k $(TEST)/TACK_Key1.pem -p asdf -s v1_key -g 1 -c $(CERT1) -o $(TEST)/TACK6.pem
	$(EXEC) update -k $(TEST)/TACK_Key1.pem -c $(CERT1) -i $(TEST)/TACK1.pem > $(TEST)/TACK1_1.pem	
	$(EXEC) up -k $(TEST)/TACK_Key1.pem -p asdf -c $(CERT2) -i $(TEST)/TACK2.pem -o $(TEST)/TACK2_1.pem		
	$(EXEC) u -k $(TEST)/TACK_Key1.pem -p asdf -s v1_key -c $(CERT1) -i $(TEST)/TACK3.pem -o $(TEST)/TACK3_1.pem			
	$(EXEC) u -k $(TEST)/TACK_Key1.pem -p asdf -s v1_cert -d 30d -g 2 -c $(CERT1) -i $(TEST)/TACK4.pem -o $(TEST)/TACK4_1.pem			
	$(EXEC) u -k $(TEST)/TACK_Key1.pem -p asdf -s v1_key -d 1d12h5m -e 2030-06-06Z -c $(CERT1) -i $(TEST)/TACK5.pem -o $(TEST)/TACK5_1.pem	
	$(EXEC) u -k $(TEST)/TACK_Key1.pem -p asdf -s v1_key -g 255 -c $(CERT1) -i $(TEST)/TACK6.pem -o $(TEST)/TACK6_1.pem
	$(EXEC) adjust -i $(TEST)/TACK1_1.pem -d 8h30m > $(TEST)/TACK1_2.pem
	$(EXEC) a -i $(TEST)/TACK2_1.pem -d 1095d1m -o $(TEST)/TACK2_2.pem
	$(EXEC) break -k $(TEST)/TACK_Key1.pem -p asdf -i $(TEST)/TACK5.pem > $(TEST)/TACK_Break_Sig5_1.pem
	$(EXEC) b -k $(TEST)/TACK_Key1.pem -p asdf -i $(TEST)/TACK5.pem -o $(TEST)/TACK_Break_Sig5_2.pem
		