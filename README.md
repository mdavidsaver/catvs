# Channel Access Tests

## Running the Tests

### Run against SoftIOC

``
SOFTIOC=/usr/bin/softIoc DUT=$PWD/wrapioc.sh python -m unittest discover catvs.server
``

or

``
SOFTIOC=/usr/bin/softIoc DUT=$PWD/wrapioc.sh nosetests catvs.server
``

### Run against PCAS

``
DUT=$PWD/pcastest/bin/linux-x86_64/pcas nosetests catvs.server
``


### Run single test

``
SOFTIOC=/usr/bin/softIoc DUT=$PWD/wrapioc.sh python -m unittest discover catvs.server.test_ops.TestArray.test_monitor_zero_dynamic
``


### Run test against standalone server (e.g in debugger)

``
TESTPORT=5064 DUT='sleep 20' python -m unittest catvs.server.test_ops.TestArray.test_monitor_zero_dynamic
``

**Then** start the test server within 2 seconds.

To relax/remove the 2 second constraint, search for 'lousy hack' in catvs/util.py


## Test Server Specs

### Server must provide the following PVs

- 'ival'
  * type DBR_LONG count 1 R/W access
  * initial value '42'

- 'aval'
  * type DBR_SHORT count 5 R/W access
  * initial size 5, values zeros

### Server must not provide the following PVs

- 'invalid'
