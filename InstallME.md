# Installation steps

change your current directory to to where the source and Makefile is located then issue:

```
git clone https://github.com/ahmedcs/HyGenICC.git
cd HyGenICC
cd KModule/
make
cd ..
cp OvS/* ~/openvswitch-2.4.0/datapath/
cd ~/openvswitch-2.4.0/datapath/
patch -p1 < hygenicc.patch
```

# OpenvSwitch version

You need to apply the patch that comes along with the source files to the "datapath" subfolder of the OpenvSwitch source directory. Notice that, the patch is customized to openvswitch version 2.4.0 and it may/may not work for other versions. If you are applying the patch to a different version, please read the patch file and update manually (few locations is updated).

The patch updates these files: (actions.c, datapath.c, datapath.h, Makefile.in, Module.mk)

Then you need to issue the patch command to patch (actions.c datapath.c, datapath.h, Makefile.in, Module.mk):

```
cd openvswitch-2.4.0/datapath
patch -p1 < iqm.patch
```

Copy the source and header files to the datapath folder (hygenicc.c, myflow.c, hygenicc.h and myflow.h), then we need to build and install the new openvswitch:

```
cd openvswtich-2.4.0
./configure --with-linux="/lib/modules/`uname -r`/build"
cd datapath
make clean
make
cd linux
sudo make modules_install
```

If the kernel module was not installed properly, it can be copied as follows (depending on the current location of the running OpenvSwitch):
```
cd openvswtich-2.4.0/datapath/linux
sudo cp openvswitch.ko /lib/modules/`uname -r`/kernel/net/openvswitch/openvswitch.ko
```

The location of the OpenvSwitch module can be found by the following:
```
modinfo openvswitch
```

# Kernel-Module Makefile update
If the source file has been changed, you need to update the name of the object file to match the new source file containing the module init_module and exit_module macros and the definition functions. SEE Makefile for more information.

Notice, you can include other source and header files but under the condition that there are a single source file containing the necessary init_module and exit_module macros and their function.


Now the output files is as follows:
```
hygenicc.o and hygenicc.ko
```
The file ending with .o is the object file while the one ending in .ko is the module file


# Run
To install the module into the kernel
```
sudo insmode hygenicc.ko
```
Now the module will do nothing until it is enabled by setting hygenicc_enable parameter as follows:   

```
sudo echo 1 > /sys/kernel/modules/iqm/parameters/hygenicc_enable;
```

Note that the parameters of the module are:  
1- hygenicc_enable: enable HyGenICC congestion control module, 0 is the default which disables packet interception.  
2- rate: the speed of the physical out link in Mbits/s, default = 1000 Mb/s.  
3- gsosize: determines the size of GSO segment, if zero default is used, default = 0  

Also to call the module with different parameters issue the following:
```
sudo insmod hygenicc.ko hygenicc_enable=0 M=10 interval=200L;
```


# Stop

To stop the loss_probe module and free the resources issue the following command:

```
sudo rmmod -f iqm;
```
