#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/poll.h>
#include <linux/random.h>

#define __DEBUG_PRINTK__

#ifdef __DEBUG_PRINTK__ 
#define debug(format,...) printk("Line: %05d: "format"\n", __LINE__, ##__VA_ARGS__)
#else 
#define debug(format,...)   
#endif 


#define CMD_SUCCESS 		(0)
#define CMD_FAILD		(-1)
#define ACK 				1
#define NACK 				0




static int major;
static dev_t devid;
static struct class *cls;
struct at88sc_t {
	char *name;
	struct cdev at88sc_cdev;
	int pin_sda;
	int pin_scl;
};
static struct at88sc_t *at88sc;


struct at88sc_ioctl_data_t{
	unsigned char zone;
	unsigned char *ioctl_buff;
	unsigned char ioctl_buff_len;
	unsigned char anti_tearing;
	unsigned char key_index;
	unsigned char fuses_id;
	unsigned char *random;
	unsigned char *passwd;
	unsigned char passwd_rw;
	unsigned char *checksum;
};

static struct at88sc_ioctl_data_t at88sc_ioctl_data;

#define I2C_CLK_LOW 		gpio_set_value(at88sc->pin_scl, 0);
#define I2C_CLK_HIGHT 	gpio_set_value(at88sc->pin_scl, 1);
#define I2C_DAT_LOW 		gpio_set_value(at88sc->pin_sda, 0);
#define I2C_DAT_HIGHT 	gpio_set_value(at88sc->pin_sda, 1);
#define I2C_DAT_OUT      	gpio_direction_output(at88sc->pin_sda, 1);
#define I2C_DAT_IN      	gpio_direction_input(at88sc->pin_sda);
#define I2C_DATA			gpio_get_value(at88sc->pin_sda);

static unsigned char cmd_buf[4];  


#define  AT88SC_CMD_MAX_NR 		10 
#define  AT88SC_CMD_MAGIC 		'x'
#define  COMMUNICATION_TEST  	_IOWR(AT88SC_CMD_MAGIC,0x01, struct at88sc_ioctl_data_t)
#define  READ_CONFIG_ZONE		_IOWR(AT88SC_CMD_MAGIC,0x02, struct at88sc_ioctl_data_t)
#define  WRITE_CONFIG_ZONE		_IOWR(AT88SC_CMD_MAGIC,0x03, struct at88sc_ioctl_data_t)
#define  READ_FUSES				_IOWR(AT88SC_CMD_MAGIC,0x04, struct at88sc_ioctl_data_t)
#define  WRITE_FUSE				_IOWR(AT88SC_CMD_MAGIC,0x05, struct at88sc_ioctl_data_t)
#define  SELECT_USER_ZONE		_IOWR(AT88SC_CMD_MAGIC,0x06, struct at88sc_ioctl_data_t)
#define  VERIFY_CRYPTO			_IOWR(AT88SC_CMD_MAGIC,0x07, struct at88sc_ioctl_data_t)
#define  VERIFY_PASSWED			_IOWR(AT88SC_CMD_MAGIC,0x08, struct at88sc_ioctl_data_t)
#define  SEND_CHECKSUM			_IOWR(AT88SC_CMD_MAGIC,0x09, struct at88sc_ioctl_data_t)
#define  READ_CHECKSUM			_IOWR(AT88SC_CMD_MAGIC,0x0A, struct at88sc_ioctl_data_t)

 void i2c_start(void)
{
	I2C_DAT_OUT;
	I2C_DAT_HIGHT;
	I2C_CLK_HIGHT;
	ndelay(250);
	I2C_DAT_LOW;
	ndelay(250);
	I2C_CLK_LOW;
	ndelay(250);
}

void i2c_stop(void)
{
	I2C_DAT_OUT;
	I2C_DAT_LOW;
	I2C_CLK_HIGHT;
	ndelay(250);
	I2C_DAT_HIGHT;
	ndelay(250);
}


void i2c_send_ack(int ack)  
{  
	I2C_DAT_OUT; 
	I2C_CLK_LOW;
	if(ack){ 
		I2C_DAT_LOW; 
	}else{       
		I2C_DAT_HIGHT; 
	}
	ndelay(250);
	I2C_CLK_HIGHT;
	ndelay(250);
	I2C_CLK_LOW;
}  


unsigned char i2c_read_ack(void)  
{  
	unsigned char ack;  
	I2C_DAT_IN;
	I2C_CLK_HIGHT; 
	ndelay(250); 
	ack = I2C_DATA;
	ndelay(250); 
	I2C_CLK_LOW;
	I2C_DAT_OUT;
	return ack;  
} 


unsigned char byte_read(void)
{
	int i;  
	unsigned char data = 0;  
	I2C_DAT_IN; 
	for (i=7; i>=0; i--) {  
		I2C_CLK_LOW;
		ndelay(250);
		data = (data <<1) | I2C_DATA;
		I2C_CLK_HIGHT; 
		ndelay(250);
	}  
	return data;  
}

unsigned char byte_write(unsigned char ucData)
{
	int i;  
	I2C_DAT_OUT;
	for (i=7; i>=0; i--) {  
		I2C_CLK_LOW; 
		ndelay(250);
		if(ucData & (1<<i)){
			I2C_DAT_HIGHT;
		}else{
			I2C_DAT_LOW;
		}
		I2C_CLK_HIGHT;
		ndelay(250);
	}  

	I2C_DAT_HIGHT;	// release SDA
	if (i2c_read_ack() != 0) {
		debug( "no acknowledge\n");
		i2c_stop();
	}
	return 0;
}


/* cmdbuff = [ cmd, addr1, addr2, N ] */
int at88sc_send_cmd(unsigned char *cmdbuff)
{
	int result = 0;
	int i = 0;
	i2c_start();
	for( i = 0; i < 4; i++){
		result = byte_write(cmdbuff[i]);
		if( result < 0){
			return CMD_FAILD;
		}
	}
	return CMD_SUCCESS;
}

unsigned char at88sc_send_data(unsigned char *sendbuff, unsigned char len)
{
	int result = 0;
	int i = 0;
	for(i = 0; i< len; i++) {
		result = byte_write(sendbuff[i]);
		if( result < 0){
			return CMD_FAILD;
		}
	}
	i2c_stop();
	return CMD_SUCCESS;
}



unsigned char at88sc_recv_data(unsigned char *sendbuff, unsigned char len)
{
	int i = 0;
	for(i = 0; i< len - 1; i++) {
		sendbuff[i] = byte_read();
		i2c_send_ack(ACK);
	}
	sendbuff[i] = byte_read();
	i2c_send_ack(NACK);
	i2c_stop();
	return CMD_SUCCESS;
}


/* ioctl */

unsigned char at88sc_read_config_zone(unsigned char zone, unsigned char*read_buff, unsigned char count)
{
	debug("zone = 0x%x\n", zone);
	debug("count = %d\n",count);
	cmd_buf[0] = 0xb6;
	cmd_buf[1] = 0x00;
	cmd_buf[2] = zone;
	cmd_buf[3] = count;
	if(at88sc_send_cmd(cmd_buf)){
		return CMD_FAILD;
	}
	at88sc_recv_data(read_buff, count);
	return CMD_SUCCESS;
}

unsigned char at88sc_read_fuses(unsigned char *fuse_id)
{
	cmd_buf[0] = 0xb6;
	cmd_buf[1] = 0x01;
	cmd_buf[2] = 0x00;
	cmd_buf[3] = 0x01;
	if(at88sc_send_cmd(cmd_buf)){
		return CMD_FAILD;
	}
	at88sc_recv_data(fuse_id, 1);
	return CMD_SUCCESS;
}

unsigned char at88sc_read_checksum(unsigned char* checksum)
{
	cmd_buf[0] = 0xb6;
	cmd_buf[1] = 0x02;
	cmd_buf[2] = 0x00;
	cmd_buf[3] = 0x02;
	if(at88sc_send_cmd(cmd_buf)){
		return CMD_FAILD;
	}
	if(at88sc_recv_data(checksum, 2)){
		return CMD_FAILD;
	}
	return CMD_SUCCESS;
}


unsigned char at88sc_write_config_zone(unsigned char zone, unsigned char*write_buff, unsigned char count, unsigned char anti_tearing)
{
	if(anti_tearing && count > 8){
		debug("The maximum number of bytes is limited 8 .");
		return CMD_FAILD;
	}

	cmd_buf[0] = 0xb4;
	if(anti_tearing){
		cmd_buf[1] = 0x08;
	}else{
		cmd_buf[1] = 0x00;
	}
	cmd_buf[2] = zone;
	cmd_buf[3] = count;
	if(at88sc_send_cmd(cmd_buf)){
		return CMD_FAILD;
	}
	at88sc_send_data(write_buff, count);
	return CMD_SUCCESS;

}


unsigned char at88sc_write_fuses(unsigned char fuse_id)
{
	cmd_buf[0] = 0xb4;
	cmd_buf[1] = 0x01;
	cmd_buf[2] = fuse_id;
	cmd_buf[3] = 00;
	if(at88sc_send_cmd(cmd_buf)){
		return CMD_FAILD;
	}
	return CMD_SUCCESS;
}


unsigned char at88sc_send_checksum(unsigned char* checksum)
{
	cmd_buf[0] = 0xb4;
	cmd_buf[1] = 0x02;
	cmd_buf[2] = 0x00;
	cmd_buf[3] = 0x02;
	if(at88sc_send_cmd(cmd_buf)){
		return CMD_FAILD;
	}
	if(at88sc_send_data(checksum, 2)){
		return CMD_FAILD;
	}
	return CMD_SUCCESS;
}


int select_user_zone(unsigned char zone, unsigned char anti_tearing)
{
	cmd_buf[0] = 0xb4;
	if(anti_tearing){
		cmd_buf[1] = 0x0b;
	}else{
		cmd_buf[1] = 0x03;
	}
	cmd_buf[2] = zone;
	cmd_buf[3] = 0x00;
	return at88sc_send_cmd(cmd_buf);
}


unsigned char at88sc_verify_crypto(unsigned char key_index,  unsigned char* random)
{
	unsigned char random_num[8];
	unsigned char chanllenge[8];
	unsigned char verify_params[16];
	unsigned char device_new_ci[8];
	unsigned char secret_seed[8];
	unsigned char cryptogram_ci[8];
	unsigned char zone;

	/* 读取设备加密种子 */
	zone = (key_index & 0x0f) * 8 + 0x90;
	if(at88sc_read_config_zone(zone, secret_seed, sizeof(secret_seed))){
		return CMD_FAILD;
	}

	/* 读取设备会话密码 */
	zone = (key_index & 0x0f) * 16 + 0x51;
	if(at88sc_read_config_zone(zone, cryptogram_ci, sizeof(cryptogram_ci))){
		return CMD_FAILD;
	}
	
	/*获取随机数*/
	if(random){
		memcpy(random_num, random, 8);
	}else{
		get_random_bytes(random_num,8);
	}

	/* F1 算法,  根据Ci, random_num, user_sk 得到一个8  字节chanllenge */
	//authen_encrypt_calculate(cryptogram_ci, random_num, secret_seed, chanllenge);

	/* 组合参数 */
	memcpy(verify_params, random_num, 8);
	memcpy(verify_params + 8, chanllenge, 8);

	/* 发送认证命令及认证参数 */
	cmd_buf[0] = 0xb8;
	cmd_buf[1] = key_index;  /* 0x0X   或0x1X */
	cmd_buf[2] = 0x00;
	cmd_buf[3] = 0x10;  /* random + chanllenge = 16 */
	if(at88sc_send_cmd(cmd_buf)){
		return CMD_FAILD;
	}
	if(at88sc_send_data(verify_params, sizeof(verify_params))){
		return CMD_FAILD;
	}

	/* 等待片刻 */
	mdelay(1);

	/* 读取认证结果 */
	zone = (key_index & 0x0f) * 16 + 0x51;
	debug("zone  = 0x%x\n",zone);
	if(at88sc_read_config_zone(zone, device_new_ci, sizeof(device_new_ci))){
		return CMD_FAILD;
	}

	/* 比较 */
	if(memcmp(cryptogram_ci, device_new_ci, 8) != 0){
		debug("authentication  faild\n");
		return CMD_FAILD;
	}

	return CMD_SUCCESS;
}


unsigned char at88sc_verify_passwd(unsigned char* passwd,  unsigned char index, unsigned char rw_flag)
{
	cmd_buf[0] = 0xba;
	cmd_buf[1] = ((rw_flag << 4) | index);  	/* rw_flag:  0:write passwd       1:read passwd */
	cmd_buf[2] = 0x00;
	cmd_buf[3] = 0x03;
	if(at88sc_send_cmd(cmd_buf)){
		return CMD_FAILD;
	}

	if(at88sc_send_data(passwd, 3)){
		return CMD_FAILD;
	}
	return CMD_SUCCESS;
}


int communication_test(unsigned char *test_data)
{
	unsigned char send_data[2];
	unsigned char recv_data[2];
	memcpy(send_data, test_data, 2);
	if(at88sc_write_config_zone(0x0a, send_data, sizeof(send_data), 0)){
		return CMD_FAILD;
	}
	if(at88sc_send_data(send_data, sizeof(send_data))){
		debug("at88sc_send_data error.");
	}
	mdelay(200);
	if(at88sc_read_config_zone(0x0a, recv_data, sizeof(recv_data))){
		return CMD_FAILD;
	}

	if(memcmp(recv_data, send_data, 2) != 0){
		debug("send_data = [0x%02x 0x%02x ]\n", send_data[0], send_data[1]);
		debug("recv_data = [0x%02x 0x%02x ]\n", recv_data[0], recv_data[1]);
		return CMD_FAILD;
	}else{
		return CMD_SUCCESS;
	}
}

static int at88_open(struct inode *inode,struct file *filp)
{
	debug("-----at88_open-------\n");

	return 0;
}

static int at88_release(struct inode *inode,struct file *filp)
{
	return 0;
}


static ssize_t at88_read (struct file *filp, char *buf, size_t count, loff_t *f_pos)
{
	return 0;
}


static ssize_t at88_write (struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
	return 0;
}




static long at88_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	if(copy_from_user(&at88sc_ioctl_data, (struct at88sc_ioctl_data_t *)arg, sizeof(struct at88sc_ioctl_data_t))){
		return -EFAULT;
	}

	 if(_IOC_TYPE(cmd) != AT88SC_CMD_MAGIC) 
		return - EINVAL;

 	if(_IOC_NR(cmd) > AT88SC_CMD_MAX_NR) 
		return - EINVAL;

	debug("anti_tearing = %d\n", at88sc_ioctl_data.anti_tearing);
	debug("ioctl_buff_len = %d\n", at88sc_ioctl_data.ioctl_buff_len);
	debug("key_index = %d\n", at88sc_ioctl_data.key_index);
	debug("zone = 0x%x\n", at88sc_ioctl_data.zone);

	switch(_IOC_NR(cmd)){
	case _IOC_NR(COMMUNICATION_TEST):
		debug("--- communication_test ---\n");
		ret = communication_test(at88sc_ioctl_data.ioctl_buff);
		break;
	case _IOC_NR(READ_CONFIG_ZONE):
		debug("--- READ_CONFIG_ZONE ---\n");
		ret = at88sc_read_config_zone(at88sc_ioctl_data.zone, at88sc_ioctl_data.ioctl_buff, at88sc_ioctl_data.ioctl_buff_len);
		break;
	case _IOC_NR(WRITE_CONFIG_ZONE):
		debug("--- WRITE_CONFIG_ZONE ---\n");
		ret = at88sc_write_config_zone(at88sc_ioctl_data.zone, at88sc_ioctl_data.ioctl_buff, at88sc_ioctl_data.ioctl_buff_len, at88sc_ioctl_data.anti_tearing);
		break;
	case _IOC_NR(READ_FUSES):
		debug("--- READ_FUSES ---\n");
		at88sc_read_fuses(&(at88sc_ioctl_data.fuses_id));
		break;
	case _IOC_NR(WRITE_FUSE):
		debug("--- WRITE_FUSE ---\n");
		at88sc_write_fuses(at88sc_ioctl_data.fuses_id);
		break;
	case _IOC_NR(SELECT_USER_ZONE):
		debug("--- SELECT_USER_ZONE ---\n");
		select_user_zone(at88sc_ioctl_data.zone, at88sc_ioctl_data.anti_tearing);
		break;
	case _IOC_NR(VERIFY_CRYPTO):
		debug("--- VERIFY_CRYPTO ---\n");
		at88sc_verify_crypto(at88sc_ioctl_data.key_index, at88sc_ioctl_data.random);
		break;
	case _IOC_NR(VERIFY_PASSWED):
		debug("--- VERIFY_PASSWED ---\n");
		at88sc_verify_passwd(at88sc_ioctl_data.passwd,  at88sc_ioctl_data.key_index, at88sc_ioctl_data.passwd_rw);
		break;
	case _IOC_NR(SEND_CHECKSUM):
		debug("--- SEND_CHECKSUM ---\n");
		at88sc_send_checksum(at88sc_ioctl_data.checksum);
		break;
	case _IOC_NR(READ_CHECKSUM):
		debug("--- READ_CHECKSUM ---\n");
		at88sc_read_checksum(at88sc_ioctl_data.checksum);
		break;

	}
	return ret;
}



static struct file_operations at88sc_fops = {
	.open		= at88_open,
	.release		= at88_release,
	.read		= at88_read,
	.write		= at88_write,
	.unlocked_ioctl	= at88_ioctl,
};


static int __init at88sc_init(void)
{
	int ret, i;

	at88sc = kmalloc(sizeof(struct at88sc_t), GFP_KERNEL);
	if(at88sc == NULL){
		return -1;
	}

	at88sc->name = "at88sc";
	at88sc->pin_scl = 228;  		//PH04
	at88sc->pin_sda = 229;			//PH05

	if (major) {
		devid = MKDEV(major, 0);
		register_chrdev_region(devid, 1, at88sc->name);  
	} else {
		alloc_chrdev_region(&devid, 0, 1, at88sc->name); 
		major = MAJOR(devid);                     
	}
	cdev_init(&at88sc->at88sc_cdev, &at88sc_fops);
	cdev_add(&at88sc->at88sc_cdev, devid, 1);

	cls = class_create(THIS_MODULE, at88sc->name);
	device_create(cls, NULL, devid, NULL, at88sc->name); 	/* /dev/at88sc */

	/*Request GPIO*/
	ret = gpio_request(at88sc->pin_scl,"AT88SC_SCL");
	if(ret){
		debug("Cannot request gpio. err = %d\n",ret);
		goto out;
	}

	ret = gpio_request(at88sc->pin_sda,"AT88SC_SDA");
	if(ret){
		debug("Cannot request gpio. err = %d\n",ret);
		goto out;
	}

	/* Pullup the GPIO */
	gpio_direction_output(at88sc->pin_scl, 1);

	/* give five clock */
	for(i = 0; i < 5; i++){
		I2C_CLK_LOW;
		ndelay(250);
		I2C_CLK_HIGHT;
		ndelay(250);
	}


	debug("-----at88sc_init-------\n");

	return 0;

out:
	
	device_destroy(cls, devid);
	class_destroy(cls);

	cdev_del(&at88sc->at88sc_cdev);
	unregister_chrdev_region(devid, 1);
	return -1;

}

static void __exit at88sc_exit(void)
{
	device_destroy(cls, devid);
	class_destroy(cls);

	cdev_del(&at88sc->at88sc_cdev);
	unregister_chrdev_region(devid, 1);

	gpio_free(at88sc->pin_scl);
	gpio_free(at88sc->pin_sda);

	
	kfree(at88sc);
	debug("-----at88sc_exit-------\n");
}

module_init(at88sc_init);
module_exit(at88sc_exit);


MODULE_AUTHOR ("www.gzseeing.com");
MODULE_DESCRIPTION("AT88SC104 DRIVER");
MODULE_LICENSE("GPL");

