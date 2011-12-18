
version := 0.9.0
version_insert := sed -e 's/VV.VV.VV/$(version)/g'
dir := TACK-tool-$(version)

clean:
	rm -rf $(dir)
	rm -f TACK-tool-*.tar.gz

release:
	rm -rf $(dir)
	mkdir $(dir)
	./make_release.py | $(version_insert) > $(dir)/TACK
	chmod +x $(dir)/TACK
	$(version_insert) README > $(dir)/README
	tar czvf $(dir).tar.gz $(dir)
