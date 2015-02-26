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
	rm -rf unit_tests/*.pyc
	rm -rf dist
	rm -rf docs
	rm -rf build
	rm -f MANIFEST

docs:
	epydoc --html -v --introspect-only -o docs --graph all tlslite

dist: docs
	./setup.py sdist

test:
	cd tests/ && python ./tlstest.py server localhost:4433 . & sleep 1
	cd tests/ && python ./tlstest.py client localhost:4433 .

test-local:
	cd tests/ && PYTHONPATH=.. python ./tlstest.py server localhost:4433 . & sleep 1
	cd tests/ && PYTHONPATH=.. python ./tlstest.py client localhost:4433 .

test-dev:
ifdef PYTHON2
	@echo "Running test suite with Python 2"
	python2 -m unittest discover -v
	cd tests/ && PYTHONPATH=.. python2 ./tlstest.py server localhost:4433 . & sleep 1
	cd tests/ && PYTHONPATH=.. python2 ./tlstest.py client localhost:4433 .
endif
ifdef PYTHON3
	@echo "Running test suite with Python 3"
	python3 -m unittest discover -v
	cd tests/ && PYTHONPATH=.. python3 ./tlstest.py server localhost:4433 . & sleep 1
	cd tests/ && PYTHONPATH=.. python3 ./tlstest.py client localhost:4433 .
endif
ifndef PYTHON2
ifndef PYTHON3
	@echo "Running test suite with default Python"
	python -m unittest discover -v
	cd tests/ && PYTHONPATH=.. python ./tlstest.py server localhost:4433 . & sleep 1
	cd tests/ && PYTHONPATH=.. python ./tlstest.py client localhost:4433 .
endif
endif
	epydoc --check --fail-on-error -v tlslite
	pylint --msg-template="{path}:{line}: [{msg_id}({symbol}), {obj}] {msg}" tlslite > pylint_report.txt || :
	diff-quality --violations=pylint --fail-under=90 pylint_report.txt

tests/TACK_Key1.pem:
	tack genkey -x -p test -o tests/TACK_Key1.pem

tests/TACK_Key2.pem:
	tack genkey -x -p test -o tests/TACK_Key2.pem

# the following needs to be used only when the server certificate gets recreated
gen-tacks: tests/TACK_Key1.pem tests/TACK_Key2.pem
	tack sign -x -k tests/TACK_Key1.pem -p test -c tests/serverX509Cert.pem -o tests/TACK1.pem
	tack sign -x -k tests/TACK_Key2.pem -p test -c tests/serverX509Cert.pem -o tests/TACK2.pem
