#!/bin/bash

rm -r /home/neu/Desktop/OPTEE/OPTEE/tee
rm -r /home/neu/Desktop/OPTEE/OPTEE/optee_client
rm -r /home/neu/Desktop/OPTEE/OPTEE/optee_os
rm -r /home/neu/Desktop/OPTEE/OPTEE/optee_test
cp -r /home/neu/Desktop/OPTEE/source/public/kernel_src/kernel/kernel-5.10/drivers/tee /home/neu/Desktop/OPTEE/OPTEE/tee 
cp -r /home/neu/Desktop/OPTEE/source/public/optee_src/optee/optee_client /home/neu/Desktop/OPTEE/OPTEE/optee_client
cp -r /home/neu/Desktop/OPTEE/source/public/optee_src/optee/optee_os /home/neu/Desktop/OPTEE/OPTEE/optee_os
cp -r /home/neu/Desktop/OPTEE/source/public/optee_src/optee/optee_test /home/neu/Desktop/OPTEE/OPTEE/optee_test
