#!/bin/bash

directories="victimsdb_lib tests"

# checks for the whole directories
for directory in $directories
do
    grep -r -n "TODO: " "$directory"
done
