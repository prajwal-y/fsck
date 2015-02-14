/* fsck.c
 * Utility to identify, parse, read, and manipulate an on-disk image of an ext2 file system.
 * author: Prajwal Yadapadithaya (Andrew ID: pyadapad)
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>     /* for memcpy() */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <sysexits.h>
#include "ext2_fs.h"

#if defined(__FreeBSD__)
#define lseek64 lseek
#endif

/* linux: lseek64 declaration needed here to eliminate compiler warning. */
extern int64_t lseek64(int, int64_t, int);

const unsigned int sector_size_bytes = 512;

const unsigned int partition_record_size = 16;

static int device;  /* disk file descriptor */

static int ebr_offset = 0;

static unsigned int block_size = 1024;

static unsigned char superblock_buf[6*512]; //Save the superblock and group descriptor

static unsigned char inode_bitmap[1024];
static unsigned char block_bitmap[1024];

typedef struct partition_entry {
	unsigned int partition_no;
	unsigned int type;
	unsigned int start_sector;
	unsigned int length;
	struct partition_entry *next;
}partition_entry;

typedef struct inode_data {
	unsigned int inode_no;
	unsigned int file_length;
	unsigned int pointers_data_block[15];
}inode_data;

/* print_sector: print the contents of a buffer containing one sector.
 *
 * inputs:
 *   char *buf: buffer must be >= 512 bytes.
 *
 * outputs:
 *   the first 512 bytes of char *buf are printed to stdout.
 *
 * modifies:
 *   (none)
 */
void print_sector (unsigned char *buf)
{
    unsigned int i;
    for (i = 0; i < sector_size_bytes; i++) {
        printf("%02x", buf[i]);
        if (!((i+1) % 32))
            printf("\n");      /* line break after 32 bytes */
        else if (!((i+1) % 4))
            printf(" ");   /* space after 4 bytes */
    }
}


/* read_sectors: read a specified number of sectors into a buffer.
 *
 * inputs:
 *   int64 start_sector: the starting sector number to read.
 *                       sector numbering starts with 0.
 *   int numsectors: the number of sectors to read.  must be >= 1.
 *   int device [GLOBAL]: the disk from which to read.
 *
 * outputs:
 *   void *into: the requested number of sectors are copied into here.
 *
 * modifies:
 *   void *into
 */
void read_sectors (int64_t start_sector, unsigned int num_sectors, void *into)
{
    ssize_t ret;
    int64_t lret;
    int64_t sector_offset;
    ssize_t bytes_to_read;

    /*if (num_sectors == 1) {
        printf("Reading sector %"PRId64"\n", start_sector);
    } else {
        printf("Reading sectors %"PRId64"--%"PRId64"\n",
               start_sector, start_sector + (num_sectors - 1));
    }*/

    sector_offset = start_sector * sector_size_bytes;

    if ((lret = lseek64(device, sector_offset, SEEK_SET)) != sector_offset) {
        fprintf(stderr, "Seek to position %"PRId64" failed: "
                "returned %"PRId64"\n", sector_offset, lret);
        exit(-1);
    }

    bytes_to_read = sector_size_bytes * num_sectors;

    if ((ret = read(device, into, bytes_to_read)) != bytes_to_read) {
        fprintf(stderr, "Read sector %"PRId64" length %d failed: "
                "returned %"PRId64"\n", start_sector, num_sectors, ret);
        exit(-1);
    }
}

		
/* write_sectors: write a buffer into a specified number of sectors.
 *
 * inputs:
 *   int64 start_sector: the starting sector number to write.
 *                	sector numbering starts with 0.
 *   int numsectors: the number of sectors to write.  must be >= 1.
 *   void *from: the requested number of sectors are copied from here.
 *
 * outputs:
 *   int device [GLOBAL]: the disk into which to write.
 *
 * modifies:
 *   int device [GLOBAL]
 */
void write_sectors (int64_t start_sector, unsigned int num_sectors, void *from)
{
    ssize_t ret;
    int64_t lret;
    int64_t sector_offset;
    ssize_t bytes_to_write;

    if (num_sectors == 1) {
        printf("Reading sector  %"PRId64"\n", start_sector);
    } else {
        printf("Reading sectors %"PRId64"--%"PRId64"\n",
               start_sector, start_sector + (num_sectors - 1));
    }

    sector_offset = start_sector * sector_size_bytes;

    if ((lret = lseek64(device, sector_offset, SEEK_SET)) != sector_offset) {
        fprintf(stderr, "Seek to position %"PRId64" failed: "
                "returned %"PRId64"\n", sector_offset, lret);
        exit(-1);
    }

    bytes_to_write = sector_size_bytes * num_sectors;

    if ((ret = write(device, from, bytes_to_write)) != bytes_to_write) {
        fprintf(stderr, "Write sector %"PRId64" length %d failed: "
                "returned %"PRId64"\n", start_sector, num_sectors, ret);
        exit(-1);
    }
}

/**
 * Read a partition entry and save the required fields for partition table
 */
partition_entry *read_partition_entry(char *part_buf, int partition_no, int sector_offset) {

	int type = (int)part_buf[4] & 0xFF;
	if (type != 0x82 && type != 0x00 && type != 0x83 && type != 0x05) {
        return NULL;
    }

	partition_entry *entry = (partition_entry*)malloc(sizeof(partition_entry));
	entry->partition_no = partition_no;
	//Save type
	entry->type = type;
	
	//Extract start address
	if(type == 0x05)
		entry->start_sector = ((((int)part_buf[11]&0xFF) << 24) | (((int)part_buf[10]&0xFF) << 16) | (((int)part_buf[9]&0xFF) << 8) | ((int)part_buf[8])&0xFF) + ebr_offset;
	else
		entry->start_sector = ((((int)part_buf[11]&0xFF) << 24) | (((int)part_buf[10]&0xFF) << 16) | (((int)part_buf[9]&0xFF) << 8) | ((int)part_buf[8])&0xFF) + sector_offset;

	//Extract end address
	entry->length = (((int)part_buf[15]&0xFF) << 24) | (((int)part_buf[14]&0xFF) << 16) | (((int)part_buf[13]&0xFF) << 8) | ((int)part_buf[12]&0xFF);
	
	entry->next = NULL;

	return entry;
}

/**
 * Given a sector and partition number, read it and extract required info
 */
partition_entry *read_partition_table(int sector, int partition_no, int sector_offset) {
	unsigned int partition_addr, i;
	unsigned char part_buf[partition_record_size];
	unsigned char buf[sector_size_bytes];        /* temporary buffer */

    read_sectors(sector, 1, buf); //Read sector into buf

	//Extract the partition to be read
	partition_addr = 446 + ((partition_no - 1) * 16);
	for(i = partition_addr; i < partition_addr + partition_record_size; i++) {
		part_buf[i-partition_addr] = buf[i];
	}

	partition_entry *part = read_partition_entry(part_buf, partition_no, sector_offset);

	return part;
}

void print_ll(partition_entry *node) {
	while(node != NULL) {
		printf("%02x, %d -> ", node->type, node->start_sector);
		node = node->next;
	}
	printf("\n");
}

partition_entry *read_sector_partitions(int sector, int sector_offset) {

	int i;
	partition_entry *entry = NULL;
	partition_entry *first = NULL; 

	int part_count = 4;
	if(sector_offset != 0)
		part_count = 2;

	for(i = 1; i <= part_count; i++) {
		partition_entry *temp = read_partition_table(sector, i, sector_offset);
		if(entry == NULL) {
			entry = temp;
			first = entry;
		}
		else if(temp != NULL){
			entry->next = temp;
			entry = entry->next;
		}
	}

	partition_entry *temp = first;
	partition_entry *end = entry;
	while(temp != end->next) {
		//If EBR, check the corresponding sector accordingly
		if(temp->type == 5) {
			if(ebr_offset == 0)
				ebr_offset = temp->start_sector;
			entry->next = read_sector_partitions(temp->start_sector, temp->start_sector);
			//Delete entries that are not needed
			partition_entry *cur = entry->next;
			partition_entry *prev = entry;
			while(cur != NULL) {
				if(cur->type == 5 || cur->type == 0) {
					if(cur->next == NULL) {
						free(cur);
						prev->next = NULL;
					}
					else {
						prev->next = cur->next;
						free(cur);
						cur = prev->next;
						continue;
					}
				}
				prev = cur;
				cur = cur->next;
			}
		}
		while(entry->next != NULL) //Not needed, can be removed.
			entry = entry->next;
		temp = temp->next;
	}
	
	return first;
}

/**
* Get the partition entry given partition number
**/
partition_entry *get_partition_entry(partition_entry *head, unsigned int partition_no) {	
	unsigned int count = 1;
	while(head != NULL) {
		if(partition_no == count) {
			return head;
		}
		head = head->next;
		count++;
	}
	return NULL;
}

/****************************************************************/

unsigned int getValueFromBytes(char *buf, int index, int size) {
	if(size == 4)
		return ((((int)buf[index+3]&0xFF) << 24) | (((int)buf[index+2]&0xFF) << 16) | (((int)buf[index+1]&0xFF) << 8) | ((int)buf[index])&0xFF);
	else if (size == 2)
		return ((((int)buf[index+1]&0xFF) << 8) | ((int)buf[index]&0xFF));
}

unsigned int get_block_starting_byte(int block_no) {
	return block_no * block_size;
}

unsigned int get_block_sector(partition_entry *entry, unsigned int block_no) {
	//printf("In get block_sector: %d, %d\n", entry->start_sector, block_no);
	return (entry->start_sector + (block_no*(block_size/sector_size_bytes)));
}

//Given an inode number, return its starting byte (offset)
unsigned int get_inode_starting_byte(unsigned int inode_no) {
	//[(block size)*(first inode block number) + (size of inode structure * (inode number - 1))]
	return (block_size * getValueFromBytes(superblock_buf, 2048+8, 4)) + (getValueFromBytes(superblock_buf, 1024+88, 2) * (inode_no-1));
}

//Given offset, return the inode number
unsigned int get_inode_number(unsigned int offset) {
	//[((offset - ((block size)*(first inode block number)))/size of inode structure)+1]
	return ((offset - (block_size * getValueFromBytes(superblock_buf, 2048+8, 4)))/getValueFromBytes(superblock_buf, 1024+88, 2))+1;
}

/*
*Scan though a directory and identify all files and directories within it.
*/
void scan_dir_data_block(partition_entry *partition, unsigned int block_no) {
	unsigned char buf[block_size];
	unsigned int i = 0, j;
	read_sectors(get_block_sector(partition, block_no), 2, buf);
	while(i < block_size-1) {
		struct ext2_dir_entry_2 file_entry;
		file_entry.inode = (__u32)getValueFromBytes(buf, i+0, 4);
		file_entry.rec_len = (__u16)getValueFromBytes(buf, i+4, 2);
		file_entry.name_len = (__u8)buf[i+6];
		file_entry.file_type = (__u8)buf[i+7];
		printf("inode, rec_len, name_len, file_type: %d, %d, %d, %d\n", file_entry.inode, file_entry.rec_len, file_entry.name_len, file_entry.file_type);
		for(j=0;j<file_entry.name_len;j++) {
			file_entry.name[j]=buf[i+8+j];
		}
		file_entry.name[file_entry.name_len] = '\0';
		printf("Name: %s\n", file_entry.name);
		i = i + file_entry.rec_len;
	}
}

/*
* Read and return the data present in an inode
*/
inode_data read_inode(partition_entry *partition, unsigned int inode_no) {
	inode_data inode;
	char buf[sector_size_bytes];
	int i;
    int inode_offset = get_inode_starting_byte(inode_no);
    int inode_sector = get_block_sector(partition, inode_offset/block_size);
    //printf("inode sector: %d\n", inode_sector);
    //the root inode does not start at the beginning of the block
    int temp = inode_offset-((inode_sector - partition->start_sector)*sector_size_bytes);
    read_sectors(inode_sector, 1, buf);
    //print_sector(buf);
    //printf("temp: %d\n", temp);
    //printf("First data block: 0x%02X 0x%02X 0x%02x 0x%02x\n", buf[temp+40], buf[temp+41], buf[temp+42], buf[temp+43]);
    //First data block
	inode.inode_no = inode_no;
	inode.file_length = getValueFromBytes(buf, temp+4, 4);
	for(i = 0; i < 15; i++) {
		inode.pointers_data_block[i] = getValueFromBytes(buf, temp+40+(i*4), 4);
	}
    return inode;
}

/*
*Check if the inode is set in inode bitmap (true=>1 and false=>0)
*/
int check_inode_bitmap(unsigned int inode_no) {
	unsigned int byte = inode_no/8;
	unsigned int offset = 7-(inode_no%8);
	return !(!(inode_bitmap[byte]&(1<<offset)));
}

/*
*Check if the block is set in the block bitmap (true=>1 and false=>0)
*/
int check_block_bitmap(unsigned int block_no) {
	unsigned int byte = block_no/8;
    unsigned int offset = 7-(block_no%8);
    return !(!(block_bitmap[byte]&(1<<offset)));
}

/*
* Read the superblock and group descriptor and print relevant info
*/
void read_superblock(partition_entry *partition) {
	printf("\n***********superblock details**********\n");
	//Reads both superblock (1024 bytes into partition 1) 
	//and group descriptor (2048 bytes into partition 1)
	read_sectors(partition->start_sector, 6, superblock_buf);
	unsigned int block_bitmap_sector = get_block_sector(partition, getValueFromBytes(superblock_buf, 2048+0, 4));
	unsigned int inode_bitmap_sector = get_block_sector(partition, getValueFromBytes(superblock_buf, 2048+4, 4));
	read_sectors(block_bitmap_sector, 1, block_bitmap); //Save the block bitmap
	read_sectors(inode_bitmap_sector, 1, inode_bitmap); //Save the inode bitmap
	//Magic number in superblock
	printf("Magic number: 0x%02X 0x%02X\n", superblock_buf[1080], superblock_buf[1081]);
	//Total number of inodes
	printf("Inode count: %d\n", getValueFromBytes(superblock_buf, 1024, 4));
	//Filesystem size in blocks
	printf("Filesystem size in blocks: %d\n", getValueFromBytes(superblock_buf, 1024+4, 4));
	//Number of reserved blocks
	printf("Number of reserved blocks: %d\n", getValueFromBytes(superblock_buf, 1024+8, 4));
	//Free blocks counter
	printf("Free blocks counter: %d\n", getValueFromBytes(superblock_buf, 1024+12, 4));
	//Free inodes counter
	printf("Free inodes counter: %d\n", getValueFromBytes(superblock_buf, 1024+16, 4));
	//First useful block (Always 1)
	printf("First useful block: 0x%02X 0x%02X 0x%02x 0x%02x\n", superblock_buf[1044], superblock_buf[1045], superblock_buf[1046], superblock_buf[1047]);
	//Block size
	printf("Block size (0-1024, 1-2048 and so on): %d\n", getValueFromBytes(superblock_buf, 1024+24, 4));
	//Size of on disk inode structure
	printf("Size of on disk inode structure: %d\n", getValueFromBytes(superblock_buf, 1024+88, 2));

	//Block number of the block bitmap
	printf("Block number of the block bitmap: %d\n", getValueFromBytes(superblock_buf, 2048+0, 4));
	//Block number of the inode bitmap
	printf("Block number of the inode bitmap: %d\n", getValueFromBytes(superblock_buf, 2048+4, 4));
	//Block of the first inode table (9th byte in the group descriptor)
	printf("First inode table block and starting byte: %d, %d(%d)\n", getValueFromBytes(superblock_buf, 2048+8, 4), get_inode_starting_byte(1), get_inode_number(5120));
	printf("\n************end of superblock details**********\n");
}

void read_root_inode(partition_entry *partition) {
	printf("\n**********root inode details**********\n");

	inode_data inode = read_inode(partition, 2);
	//First data block
	unsigned int first_data_block = inode.pointers_data_block[0];
	printf("First data block: %d\n", first_data_block);
	
	//First data sector
	unsigned int first_data_sector = get_block_sector(partition, first_data_block);
	char data_buf[2*sector_size_bytes];
	read_sectors(first_data_sector, 2, data_buf);
	//print_sector(data_buf);

	struct ext2_dir_entry root_dir;
	root_dir.inode = (__u32)getValueFromBytes(data_buf, 0, 4);
	root_dir.rec_len = (__u16)getValueFromBytes(data_buf, 4, 2);
	root_dir.name_len = (__u16)data_buf[6];
	printf("inode, rec_len, name_len: %d, %d, %d\n", root_dir.inode, root_dir.rec_len, root_dir.name_len);
	unsigned int i;
	for(i=0;i<root_dir.name_len;i++) {
		root_dir.name[root_dir.name_len-1-i]=data_buf[8+i];
	}
	root_dir.name[root_dir.name_len] = '\0';
	printf("Name: %s\n", root_dir.name);

	char tt[5] = {'l', 'i', 'o', 'n', 's'};
	for(i=0;i<sector_size_bytes;i++) {
		if(tt[0] == data_buf[i] && tt[1]==data_buf[i+1] && tt[2]==data_buf[i+2] && tt[3]==data_buf[i+3] && tt[4]==data_buf[i+4]) {
				printf("yay! %d\n", i);
				printf("/lions inode: %d\n", getValueFromBytes(data_buf, i-8, 4));
				break;
		}
	}

	printf("\n*********end of root inode details*******\n");

	scan_dir_data_block(partition, first_data_block);
}



/****************************************************************/

int main (int argc, char **argv)
{
	int opt;	
	int partition_no = -1;
	char *disk_image;
	//Check if number of arguments is 5
	if(argc < 5) {
		printf("Incorrect number of arguments. Usage:  ./myfsck -p <partition number> -i </path/to/disk/image>\n");
		exit(EX_USAGE);
	}
	//Read command line arguments
	while ((opt = getopt(argc, argv, "p:i:")) != -1) {
    	switch (opt)
	    {
    		case 'p':
        		partition_no = atoi(optarg);
		        break;
	    	case 'i':
    	    	disk_image = optarg;
	        	break;
		    default:
    	    	fprintf(stderr, "Usage: ./myfsck -p <partition number> -i </path/to/disk/image>\n");
        		exit(EX_USAGE);
    	}
	} 

    if ((device = open(disk_image, O_RDWR)) == -1) {
        perror("Could not open device file");
        exit(-1);
    }

	partition_entry *entry = read_sector_partitions(0, 0);

	if(partition_no != -1) {
		partition_entry *partition = get_partition_entry(entry, partition_no);
		if(partition != NULL) {
			printf("0x%02X %d %d\n", partition->type, partition->start_sector, partition->length);
		}
		else {
			printf("-1\n");
	        return EX_DATAERR;
		}
	}
	//Read superblock
	read_superblock(entry);
	//Read root inode
	read_root_inode(entry);
	close(device);
	return 0;
}

/* EOF */
