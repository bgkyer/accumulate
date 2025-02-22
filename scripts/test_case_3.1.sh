#!/bin/bash
#
# test case 3.1
#
# create an adi token account 
# server IP:Port needed unless defaulting to localhost
#
# set cli command and see if it exists
#
export cli=../cmd/cli/cli

if [ ! -f $cli ]; then
        echo "cli command not found in ../cmd/cli, attempting to build"
        ./build_cli.sh
        if [ ! -f $cli ]; then
                echo "cli command failed to build"
                exit 0
        fi
fi

# call cli account generate
#
ID=`./cli_create_id.sh $1`

echo $ID

# see if we got an id, if not, exit

if [ -z $ID ]; then
   echo "Account creation failed"
   exit 0
fi

# call cli faucet 

TxID=`./cli_faucet.sh $ID $1`

# get our balance

bal=`./cli_get_balance.sh $ID $1`

echo $bal

# generate a key

Key=`./cli_key_generate.sh t31key $1`

echo $key

# create account

echo `./cli_adi_create_account.sh $ID acc://t31acct t31key $1`

echo `./cli account create acc://t31acct t31key acc://t31acct/myacmeacct acc://ACME acc://t31acct/ssg0 -s http://$1/v1`

