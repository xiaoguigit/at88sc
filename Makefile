KERN_DIR = /opt/uwork/sina33-v2/vendor/softwinner/linux-3.4

all:
	make -C $(KERN_DIR)  M=`pwd` modules 

clean:
	make -C $(KERN_DIR) M=`pwd` modules clean
	rm -rf modules.order

obj-m	+= at88sc0104.o
