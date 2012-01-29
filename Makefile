
.PHONY : default
default:
	@echo To install tlslite run \"setup.py install\"

.PHONY : clean
clean:
	rm -rf dist
	rm -rf docs
	rm -rf build

docs:
	epydoc --html -o docs tlslite

dist: docs
	./setup.py sdist