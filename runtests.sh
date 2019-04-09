#!/bin/bash

set -e

COVERAGE_THRESHOLD=90


echo "Create Virtualenv for Python deps ..."
function prepare_venv() {
    VIRTUALENV="$(which virtualenv)"
    if [ $? -eq 1 ]
    then
        # python34 which is in CentOS does not have virtualenv binary
        VIRTUALENV="$(which virtualenv-3)"
    fi
    if [ $? -eq 1 ]; then
        # still don't have virtual environment -> use python3.4 directly
        python3.4 -m venv venv && source venv/bin/activate && python3 "$(which pip3)" install -r integration_tests/requirements.txt && python3 "$(which pip3)" install -r tests/requirements.txt && python3 "$(which pip3)" install -r requirements.txt && python3 "$(which pip3)" install git+https://github.com/fabric8-analytics/fabric8-analytics-worker.git@561636c
    else
        ${VIRTUALENV} -p python3 venv && source venv/bin/activate
    if [ $? -ne 0 ]
    then
        printf "%sPython virtual environment can't be initialized%s" "${RED}" "${NORMAL}"
        exit 1
    fi
    pip install -U pip
    python3 "$(which pip3)" install -r requirements.txt

}

[ "$NOVENV" == "1" ] || prepare_venv || exit 1

$(which pip3) install pytest
$(which pip3) install pytest-cov
$(which pip3) install codecov

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=`pwd` python3 "$(which pytest)" --cov=victimsdb_lib/ --cov-report term-missing --cov-fail-under=$COVERAGE_THRESHOLD -vv -s tests/

printf "%stests passed%s\n\n" "${GREEN}" "${NORMAL}"

codecov --token=0c52dc5d-f4a6-438a-8683-fc430f10d434

