# Authors: 
#   Trevor Perrin
#   Hubert Kario - test and test-dev
#
PYTHON2 := $(shell which python2 2>/dev/null)
PYTHON3 := $(shell which python3 2>/dev/null)

.PHONY : default
default:
	@echo To install tlslite run \"./setup.py install\" or \"make install\"

.PHONY: install
install:
	./setup.py install

.PHONY : clean
clean:
	rm -rf tlslite/*.pyc
	rm -rf tlslite/utils/*.pyc
	rm -rf tlslite/integration/*.pyc	
	rm -rf dist
	rm -rf docs
	rm -rf build
	rm -f MANIFEST

docs:
	epydoc --html -v --introspect-only -o docs tlslite

dist: docs
	./setup.py sdist

test:
	cd tests/ && python ./tlstest.py server localhost:4433 . & sleep 1
	cd tests/ && python ./tlstest.py client localhost:4433 .

test-dev:
ifdef PYTHON2
	@echo "Running test suite with Python 2"
	PYTHONPATH=. python2 tests/test_tlslite_messages.py -v
endif
ifdef PYTHON3
	@echo "Running test suite with Python 3"
	PYTHONPATH=. python3 tests/test_tlslite_messages.py -v
endif
ifndef PYTHON2
ifndef PYTHON3
	@echo "Running test suite with default Python"
	PYTHONPATH=. python tests/test_tlslite_messages.py -v
endif
endif
	cd tests/ && PYTHONPATH=.. python ./tlstest.py server localhost:4433 . & sleep 1
	cd tests/ && PYTHONPATH=.. python ./tlstest.py client localhost:4433 .
