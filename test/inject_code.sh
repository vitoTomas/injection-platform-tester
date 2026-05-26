#!/bin/bash

# Test code injection via shared object.

sudo ../build/ipt -t ../build/test -r reroute -i ../build/injectable.so -s some_function
