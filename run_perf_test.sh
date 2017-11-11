#! /bin/bash

set -e

BESS_DIR="/home/shinae/bess"
BESS_CTL=$BESS_DIR/bin/bessctl

# Start BESS and open vport for containers
$BESS_CTL daemon start
C_BATCH=3000 C_PACKET=200 C_BYTE=10 \
	$BESS_CTL run perftest/chain
C_BATCH=3000 C_PACKET=200 C_BYTE=10 \
	$BESS_CTL run perftest/split
C_BATCH=3000 C_PACKET=200 C_BYTE=10 \
	$BESS_CTL run perftest/merge
C_BATCH=3000 C_PACKET=200 C_BYTE=10 \
	$BESS_CTL run perftest/merge_asym
C_BATCH=3000 C_PACKET=200 C_BYTE=10 \
	$BESS_CTL run perftest/complex_split
C_BATCH=3000 C_PACKET=200 C_BYTE=10 \
	$BESS_CTL run perftest/complex_merge

