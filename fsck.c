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
#include <math.h>
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

static struct ext2_super_block super_block;

static unsigned int lost_found_inode = -1;

static unsigned int inode_map[100000] = {0};
static unsigned int inode_link_count[100000] = {0};
static unsigned int block_map[100000] = {0};

typedef struct partition_entry {
	unsigned int partition_no;
	unsigned int type;
	unsigned int start_sector;
	unsigned int length;
	struct partition_entry *next;
}partition_entry;

typedef struct inode_data {
	unsigned int inode_no;
	unsigned int file_type;
	unsigned int file_length;
	unsigned int no_hard_links;
	unsigned int no_data_blocks;
	unsigned int pointers_data_block[15];
}inode_data;

inode_data read_inode(partition_entry *partition, unsigned int inode_no); //Reading inode entry

unsigned int read_data_blocks(partition_entry *partition, unsigned int inode, unsigned int p_inode, unsigned int *pointers, int pass_no, int perform_check, int file_type);

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

    /*if (num_sectors == 1) {
        printf("Reading sector  %"PRId64"\n", start_sector);
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

unsigned int get_inode_table_block_no(unsigned int inode_no) {
	unsigned int group_index = (inode_no-1)/super_block.s_inodes_per_group;
	unsigned int group_offset = (inode_no-1)%super_block.s_inodes_per_group;
	//printf("inode table block number for inode: %d: %d\n", inode_no, getValueFromBytes(superblock_buf, 2048+(group_index*32)+8, 4));
	return getValueFromBytes(superblock_buf, 1024+block_size+(group_index*32)+8, 4);
}

unsigned int get_block_starting_byte(int block_no) {
	return block_no * block_size;
}

unsigned int get_block_sector(partition_entry *partition, unsigned int block_no) {
	//printf("In get block_sector: %d, %d\n", entry->start_sector, block_no);
	return (partition->start_sector + (block_no*(block_size/sector_size_bytes)));
}

//Given an inode number, return its starting byte (offset)
unsigned int get_inode_starting_byte(unsigned int inode_no) {
	//[(block size)*(first inode block number) + (size of inode structure * (inode number - 1))]
	//return (block_size * getValueFromBytes(superblock_buf, 2048+8, 4)) + (getValueFromBytes(superblock_buf, 1024+88, 2) * (inode_no-1));
	return (block_size * get_inode_table_block_no(inode_no)) + (super_block.s_inode_size * ((inode_no-1)%super_block.s_inodes_per_group));
}

//Given offset, return the inode number
unsigned int get_inode_number(unsigned int offset) {
	//[((offset - ((block size)*(first inode block number)))/size of inode structure)+1]
	//return ((offset - (block_size * ))/super_block.s_inode_size)+1;
	//return ((offset - (block_size * get_inode_table_block_no(inode_no)))/super_block.s_inode_size)+1;
	return 0;
}

/*
*Scan though a directory and identify all files and directories within it.
*/
void scan_dir_data_block(partition_entry *partition, unsigned int block_no) {
	unsigned char buf[block_size];
	unsigned int i = 0, j;
	read_sectors(get_block_sector(partition, block_no), (block_size/sector_size_bytes), buf);
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
* Write the unreferenced inode to /lost+found
*/
void write_inode_entry(partition_entry *partition, unsigned int inode_no) {
	inode_data inode = read_inode(partition, lost_found_inode);
	inode_data inode_cur = read_inode(partition, inode_no);
	unsigned int block_no = read_data_blocks(partition, lost_found_inode, (block_size/sector_size_bytes), inode.pointers_data_block, 0, 0, 2);
	printf("block_no is %d\n", block_no);
	unsigned int block_sector = get_block_sector(partition, block_no);
	unsigned char buf[block_size];
	unsigned int i = 0;
	read_sectors(block_sector, (block_size/sector_size_bytes), buf);
	while(i < block_size-1) {
		struct ext2_dir_entry_2 *file_entry = (struct ext2_dir_entry_2 *)(buf+i);
		if(file_entry->rec_len > ((((__u16)8 + file_entry->name_len)+3) & ~0x03)) {
			//Change the size of the previous directory entry
			file_entry->rec_len = (((__u16)8 + file_entry->name_len)+3) & ~0x03;
			printf("new file entry length= %d\n", file_entry->rec_len);
			i = i + file_entry->rec_len;
			printf("new i: %d\n", i);
			file_entry = (struct ext2_dir_entry_2*)(buf+i);
			file_entry->inode = inode_no;
			sprintf(file_entry->name, "%d", inode_no);
			file_entry->rec_len = (__u16)(block_size-i);
			file_entry->name_len = (__u8)(strlen(file_entry->name));
			if(!(inode_cur.file_type & EXT2_S_IFREG) == 0)
				file_entry->file_type = 1;
			else if (!(inode_cur.file_type & EXT2_S_IFDIR) == 0)
				file_entry->file_type = 2;
			write_sectors(block_sector, (block_size/sector_size_bytes), buf);
			return;
		}
		else {
			i = i + file_entry->rec_len;
		}
	}
}

/*
*Funtion to parse the directory entries in a file system recursively
*if perform_check == 0, only the given directory is parsed.
*Checks are performed only if perform_check == 1
*/
unsigned int parse_filesystem(partition_entry *partition, unsigned int block_no, unsigned int pass_no, unsigned int cur_inode, unsigned int parent_inode, int perform_check) {	
	unsigned char buf[block_size];
	unsigned int i = 0, j;
	struct ext2_dir_entry_2 *file_entry;
	unsigned int block_sector = get_block_sector(partition, block_no);
	read_sectors(block_sector, (block_size/sector_size_bytes), buf);
	//printf("Reading block: %d and sector: %d\n", block_no, block_sector);
	while(i < block_size-1) {
		
		file_entry = (struct ext2_dir_entry_2 *)(buf+i);
		//printf("inode, rec_len, name_len, file_type: %d, %d, %d, %d\n", file_entry->inode, file_entry->rec_len, file_entry->name_len, file_entry->file_type);

		/*if(file_entry->inode == 0) {
			printf("what the fuck! %d\n", (block_size - 1 - i));
			if(perform_check) {
				return -1;
			}
			else {
				printf("what the fuck! %d\n", (block_size - 1 - i));
				if((block_size - 1 - i) > 16) //Enough to save the inode entry in /lost+found
					return block_no;
				else
					return -1;
			}
		}*/
		if(file_entry->inode == 0)
			return -1;
		
		//file_entry->name[file_entry->name_len] = '\0';

		//Save the inode of /lost+found
		if(cur_inode == 2 && parent_inode == 2 && (strcmp(file_entry->name, "lost+found")==0)) {
			lost_found_inode = file_entry->inode;
		}

		//Pass 1: Checking correctness for "." and ".."
		if(pass_no == 1 && perform_check) {
			//Check if "." or ".." has all correct entries
			if(file_entry->inode != cur_inode && (strcmp(file_entry->name, ".")==0)) {
				printf("current inode value is incorrect bro! %d and %d for %s\n", file_entry->inode, cur_inode, file_entry->name);
				file_entry->inode = cur_inode;
				printf("New inode to be changed: %d\n", getValueFromBytes(buf, i+0, 4));
				write_sectors(block_sector, (block_size/sector_size_bytes), buf);
			}
			if(file_entry->inode != parent_inode && (strcmp(file_entry->name, "..")==0)) {
				printf("parent inode value is incorrect bro! %d and %d for %s\n", file_entry->inode, parent_inode, file_entry->name);
				file_entry->inode = parent_inode;
				printf("New inode to be changed: %d\n", getValueFromBytes(buf, i+0, 4));
                write_sectors(block_sector, (block_size/sector_size_bytes), buf);
			}
		}

		else if (pass_no == 2 && perform_check) {
			inode_map[file_entry->inode] = 1;
		}
		else if (pass_no == 3 && perform_check) {
			inode_link_count[file_entry->inode] += 1;
		}		
		else if (pass_no == 4 && perform_check) {
			if(block_no == 2137 || block_no == 18225 || block_no == 15073 || block_no == 725)
				printf("Block found in here 3: %d\n", block_no);
			block_map[block_no] = 1;
		}

		//printf("Name: %s\n", file_entry->name);
		//i = i + file_entry->rec_len;
		if(strcmp(file_entry->name, ".") != 0 && strcmp(file_entry->name, "..") != 0 && perform_check) {
			inode_data inode = read_inode(partition, file_entry->inode);
			//printf("inode type check: %x\n", (inode.file_type&0xF000));
			if((inode.file_type & 0xF000) == 0x8000 && pass_no == 4) {
				/*if(file_entry->inode == 35)
					printf("what the fuck!? %s\n", file_entry->name);*/
				read_data_blocks(partition, file_entry->inode, cur_inode, inode.pointers_data_block, pass_no, perform_check, 1);
			}
			else if(!(inode.file_type & EXT2_S_IFDIR) == 0){
				read_data_blocks(partition, file_entry->inode, cur_inode, inode.pointers_data_block, pass_no, perform_check, 2);
			}
		}
		i = i + file_entry->rec_len;
		//printf("\nEnd of %s---------------------\n\n", file_entry->name);
	}
	//SUPER UGLY! :(
	if(file_entry != NULL && 
		file_entry->rec_len > 8+file_entry->name_len && 
		(file_entry->rec_len-8-file_entry->name_len)>16  
		&& !perform_check)
		return block_no;
	return -1;
}

/*
*read the indirect block for parsing directory entries/data block
*/
unsigned int read_indirect_data_blocks(partition_entry *partition, 
										unsigned int inode, 
										unsigned int p_inode, 
										unsigned int block_no, 
										unsigned int indirection_level, 
										int pass_no, 
										int perform_check,
										int file_type) {
	unsigned int count = 0, i = 0;
	int ret_val = -1;
	char buf[block_size];
	unsigned int sector = get_block_sector(partition, block_no);
	read_sectors(sector, (block_size/sector_size_bytes), buf);
	//printf("Is it here?\n");
	for(i = 0; i < block_size; i+=4) {
		unsigned int block = getValueFromBytes(buf, i, 4);
		if(block != 0 && (indirection_level == 3 || indirection_level == 2))
			return read_indirect_data_blocks(partition, inode, p_inode, block, indirection_level-1, pass_no, perform_check, file_type);
		else if(indirection_level == 1 && block != 0) {
			if(file_type != 1)	
				ret_val = parse_filesystem(partition, block, pass_no, inode, p_inode, perform_check);
			if(pass_no == 4) {
				if(block == 2137 || block == 18225 || block == 15073 || block == 725) {
                	printf("Block found in here 2: %d, %d, %d\n", block, inode, i);
					//print_sector(buf);
				}
				//block_map[block] = 1;
                continue;
			}
			if(ret_val != -1 && !perform_check)
				return ret_val;
			return -1;
		}
	}
	return -1;
}

/*
* Read the data blocks for parsing directory entry/Data block
*/
unsigned int read_data_blocks(partition_entry *partition, 
								unsigned int inode, 
								unsigned int p_inode, 
								unsigned int *pointers, 
								int pass_no, 
								int perform_check,
								int file_type) {
	//UGLY CODE ALERT!
	int count = 0, i = 0, ret_val = -1;
	for(i = 0; i < 12; i++) {
		//printf("In read_data_blocks\n");
		if(pointers[i] != 0) {
			if(pointers[i] == 2137 || pointers[i] == 18225 || pointers[i] == 15073 || pointers[i] == 725)
                printf("Block found in here 1: %d\n", pointers[i]);
			block_map[pointers[i]] = 1;
			if(file_type != 1)
				ret_val = parse_filesystem(partition, pointers[i], pass_no, inode, p_inode, perform_check);
			if(pass_no == 4)
				continue;
		}
		//printf("ret_val: %d\n", ret_val);
		if(!perform_check && ret_val != -1)
			return ret_val;
	}
	if(pointers[12] != 0)
		ret_val = read_indirect_data_blocks(partition, inode, p_inode, pointers[12], 1, pass_no, perform_check, file_type);
	if(!perform_check && ret_val != -1)
            return ret_val;

	if(pointers[13] != 0)
        ret_val = read_indirect_data_blocks(partition, inode, p_inode, pointers[13], 2, pass_no, perform_check, file_type); //Second level of indirection
	if(!perform_check && ret_val != -1)
            return ret_val;

	if(pointers[14] != 0)
        ret_val = read_indirect_data_blocks(partition, inode, p_inode, pointers[14], 3, pass_no, perform_check, file_type); //Third level of indirection
    
	return ret_val;
}

/*
* Update hard links counter in an inode
*/
void update_hard_link_counter(partition_entry *partition, unsigned int inode_no, unsigned int hard_link_count) {
    char buf[block_size];
    int i;
    int inode_offset = get_inode_starting_byte(inode_no);
    int inode_sector = get_block_sector(partition, inode_offset/block_size);
	int temp = inode_offset-((inode_sector - partition->start_sector)*sector_size_bytes);
    read_sectors(inode_sector, (block_size/sector_size_bytes), buf);
	struct ext2_inode *inode = (struct ext2_inode *)(buf+temp);
	inode->i_links_count = (__u16)hard_link_count;
	write_sectors(inode_sector, (block_size/sector_size_bytes), buf);
}

void update_inode_entry_to_file(partition_entry *partition, unsigned int inode_no) {
	char buf[block_size];
    int i;
    int inode_offset = get_inode_starting_byte(inode_no);
    int inode_sector = get_block_sector(partition, inode_offset/block_size);
    int temp = inode_offset-((inode_sector - partition->start_sector)*sector_size_bytes);
    read_sectors(inode_sector, (block_size/sector_size_bytes), buf);
    struct ext2_inode *inode = (struct ext2_inode *)(buf+temp);
    inode->i_mode &= 0x80FF;
    write_sectors(inode_sector, (block_size/sector_size_bytes), buf);
}

/*
* Read and return the data present in an inode
*/
inode_data read_inode(partition_entry *partition, unsigned int inode_no) {
	inode_data inode;
	char buf[block_size];
	int i;
    int inode_offset = get_inode_starting_byte(inode_no);
    int inode_sector = get_block_sector(partition, inode_offset/block_size);
	//if(inode_no == 32)
    //printf("inode offset, inode sector: %d, %d\n", inode_offset, inode_sector);
    //the root inode does not start at the beginning of the block
    int temp = inode_offset-((inode_sector - partition->start_sector)*sector_size_bytes);
    read_sectors(inode_sector, (block_size/sector_size_bytes), buf);
    /*if(inode_no == 32) {
	print_sector(buf);
    printf("temp: %d\n", temp);
    printf("First data block: 0x%02X 0x%02X 0x%02x 0x%02x\n", buf[temp+40], buf[temp+41], buf[temp+42], buf[temp+43]);
	}*/
    //First data block
	inode.inode_no = inode_no;
	inode.file_type = getValueFromBytes(buf, temp+0, 2);
	inode.file_length = getValueFromBytes(buf, temp+4, 4);
	inode.no_hard_links = getValueFromBytes(buf, temp+26, 2);
	inode.no_data_blocks = getValueFromBytes(buf, temp+28, 4);
	for(i = 0; i < 15; i++) {
		inode.pointers_data_block[i] = getValueFromBytes(buf, temp+40+(i*4), 4);
	}
    return inode;
}

/*
*Check if the inode is set in inode bitmap (true=>1 and false=>0)
*/
int check_inode_bitmap(partition_entry *partition, unsigned int inode_no) {
	if(inode_no == 0)
		return 0;
	unsigned char inode_bitmap[block_size];
	unsigned int group_index = (inode_no-1)/super_block.s_inodes_per_group;
    unsigned int inode_offset = (inode_no-1)%super_block.s_inodes_per_group;
	//printf("group index, block_offset: %d, %d\n", group_index, inode_offset);
	//printf("inode_no, inode bitmap block number: %d, %d\n", inode_no, getValueFromBytes(superblock_buf, 2048+(group_index*32)+4, 4));
	unsigned int inode_bitmap_sector = get_block_sector(partition, getValueFromBytes(superblock_buf, 1024+block_size+(group_index*32)+4, 4));
	read_sectors(inode_bitmap_sector, block_size/sector_size_bytes, inode_bitmap);
	unsigned int byte = inode_offset/8;
    unsigned int offset = 7-(inode_offset%8);
    return !(!(inode_bitmap[byte]&(1<<offset)));
}

/*
*set the value of the block bitmap to the passed value
*/
void set_block_bitmap(partition_entry *partition, unsigned int block_no, int value) {
    if(block_no == 0)
        return;
    unsigned char block_bitmap[block_size];
    unsigned int group_index = (block_no-1)/super_block.s_blocks_per_group;
    unsigned int block_offset = (block_no-1)%super_block.s_blocks_per_group;
    //printf("group index, block_offset: %d, %d\n", group_index, block_offset);
    //printf("block_no, block bitmap block number: %d, %d\n", block_no, getValueFromBytes(superblock_buf, 1024+block_size+(group_index*32)+0, 4));
    unsigned int block_bitmap_sector = get_block_sector(partition, getValueFromBytes(superblock_buf, 1024+block_size+(group_index*32)+0, 4));
	//printf("block_bitmap_sector: %d\n", block_bitmap_sector);
    read_sectors(block_bitmap_sector, (block_size/sector_size_bytes), block_bitmap);
    unsigned int byte = block_offset/8;
    unsigned int offset = 7-(block_offset%8);
	//printf("byte: %d, before: %02x, this: %02x\n", byte, block_bitmap[byte], (1<<offset));
    block_bitmap[byte] |= (1<<offset);
	write_sectors(block_bitmap_sector, (block_size/sector_size_bytes), block_bitmap);
}

/*
*Check if the block is set in the block bitmap (true=>1 and false=>0)
*/
int check_block_bitmap(partition_entry *partition, unsigned int block_no) {
	if(block_no == 0)
		return 0;
	unsigned char block_bitmap[block_size];
	unsigned int group_index = (block_no-1)/super_block.s_blocks_per_group;
    unsigned int block_offset = (block_no-1)%super_block.s_blocks_per_group;
	unsigned int block_bitmap_sector = get_block_sector(partition, getValueFromBytes(superblock_buf, 1024+block_size+(group_index*32)+0, 4));
	read_sectors(block_bitmap_sector, (block_size/sector_size_bytes), block_bitmap);
	/*if(block_no == 2137 || block_no == 18225 || block_no == 15073) {
		printf("group index, block_offset, block_bitmap_sector, byte, block_bitmap[byte]: %d, %d, %d, %d, %x\n", group_index, block_offset, block_bitmap_sector, block_offset/8, block_bitmap[block_offset/8]);
		printf("block_no, block bitmap block number: %d, %d\n", block_no, getValueFromBytes(superblock_buf, 2048+(group_index*32)+0, 4));
	}*/
	unsigned int byte = block_offset/8;
    unsigned int offset = 7-(block_offset%8);
    return !(!(block_bitmap[byte]&(1<<offset)));
}

/*
*read the indirect blocks for bitmap count
*/
int get_indirect_data_block_count(partition_entry *partition, unsigned int block_no, unsigned int indirection_level) {
	int count = 0;
	unsigned int i = 0;
	char buf[block_size];
	unsigned int sector = get_block_sector(partition, block_no);
	read_sectors(sector, (block_size/sector_size_bytes), buf);
	for(i = 0; i < block_size; i+=4) {
		if(indirection_level == 3 || indirection_level == 2)
			count += get_indirect_data_block_count(partition, getValueFromBytes(buf, i, 4), indirection_level-1);
		else if(indirection_level == 1)
			count += check_block_bitmap(partition, getValueFromBytes(buf, i, 4));
	}
	return count;
}

int get_data_block_count(partition_entry *partition, unsigned int *pointers) {
	int count = 0, i = 0;
	for(i = 0; i < 12; i++) {
		if(check_block_bitmap(partition, pointers[i]))
			count++;
	}
	if(pointers[12] != 0)
		count += get_indirect_data_block_count(partition, pointers[12], 1);
	if(pointers[13] != 0)
        count += get_indirect_data_block_count(partition, pointers[13], 2); //Second level of indirection
	if(pointers[14] != 0)
        count += get_indirect_data_block_count(partition, pointers[14], 3); //Third level of indirection
	return count;
}

/*
* Read the superblock and group descriptor and print relevant info
*/
void read_superblock(partition_entry *partition) {
	printf("\n***********superblock details**********\n");
	//Reads both superblock (1024 bytes into partition 1) 
	//and group descriptor (2048 bytes into partition 1)
	read_sectors(partition->start_sector, 6, superblock_buf);
	/*unsigned int block_bitmap_sector = get_block_sector(partition, getValueFromBytes(superblock_buf, 2048+0, 4));
	unsigned int inode_bitmap_sector = get_block_sector(partition, getValueFromBytes(superblock_buf, 2048+4, 4));
	read_sectors(block_bitmap_sector, 1, block_bitmap); //Save the block bitmap
	read_sectors(inode_bitmap_sector, 1, inode_bitmap); //Save the inode bitmap*/

	//Magic number in superblock
	printf("Magic number: 0x%02X 0x%02X\n", superblock_buf[1080], superblock_buf[1081]);
	super_block.s_magic = getValueFromBytes(superblock_buf, 1080, 2);

	//Total number of inodes
	printf("Inode count: %d\n", getValueFromBytes(superblock_buf, 1024, 4));
	super_block.s_inodes_count = getValueFromBytes(superblock_buf, 1024, 4);

	//Filesystem size in blocks
	printf("Filesystem size in blocks: %d\n", getValueFromBytes(superblock_buf, 1024+4, 4));
	super_block.s_blocks_count = getValueFromBytes(superblock_buf, 1024+4, 4);

	//Number of reserved blocks
	printf("Number of reserved blocks: %d\n", getValueFromBytes(superblock_buf, 1024+8, 4));
	super_block.s_r_blocks_count = getValueFromBytes(superblock_buf, 1024+8, 4);

	//Free blocks counter
	printf("Free blocks counter: %d\n", getValueFromBytes(superblock_buf, 1024+12, 4));
	super_block.s_free_blocks_count = getValueFromBytes(superblock_buf, 1024+12, 4);

	//Free inodes counter
	printf("Free inodes counter: %d\n", getValueFromBytes(superblock_buf, 1024+16, 4));
	super_block.s_free_inodes_count = getValueFromBytes(superblock_buf, 1024+16, 4);

	//Number of blocks per group
	printf("Number of blocks per group: %d\n", getValueFromBytes(superblock_buf, 1024+32, 4));
	super_block.s_blocks_per_group = getValueFromBytes(superblock_buf, 1024+32, 4);
	
	//Number of inodes per group
	printf("Number of inodes per group: %d\n", getValueFromBytes(superblock_buf, 1024+40, 4));
	super_block.s_inodes_per_group = getValueFromBytes(superblock_buf, 1024+40, 4);

	//First useful block (Always 1)
	printf("First useful block: 0x%02X 0x%02X 0x%02x 0x%02x\n", superblock_buf[1044], superblock_buf[1045], superblock_buf[1046], superblock_buf[1047]);

	//Block size
	printf("Block size (0-1024, 1-2048 and so on): %d\n", getValueFromBytes(superblock_buf, 1024+24, 4));
	super_block.s_log_block_size = getValueFromBytes(superblock_buf, 1024+24, 4);

	//Size of on disk inode structure
	printf("Size of on disk inode structure: %d\n", getValueFromBytes(superblock_buf, 1024+88, 2));
	super_block.s_inode_size = getValueFromBytes(superblock_buf, 1024+88, 2);

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
	read_sectors(first_data_sector, (block_size/sector_size_bytes), data_buf);
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
				//printf("/lions inode: %d\n", getValueFromBytes(data_buf, i-8, 4));
				break;
		}
	}

	printf("\n*********end of root inode details*******\n");

	//Root inode data block
	//scan_dir_data_block(partition, first_data_block);
	//read_data_blocks(partition, 2, 2, inode.pointers_data_block, 1, 1);
	
	//Pass 1
	read_data_blocks(partition, 2, 2, inode.pointers_data_block, 1, 1, 2);

	//Pass 2
	read_data_blocks(partition, 2, 2, inode.pointers_data_block, 2, 1, 2);
	for(i=1; i<=super_block.s_inodes_count; i++) {
		unsigned int bitmap_value = check_inode_bitmap(partition, i);
		if(bitmap_value == 1 && inode_map[i] == 0) {
			inode_data in = read_inode(partition, i);
			if(in.file_type != 0) { //Need to revisit this if condition
				printf("Inode %d (type: 0x%x) is not correct bro! bitmap value:%d, collected_value:%d\n", i, in.file_type, bitmap_value, inode_map[i]);
				/*if(in.file_type && 0x8000 == 0)
					update_inode_entry_to_file(partition, i);*/
				write_inode_entry(partition, i);
			}
		}
	}
	//need to repeat pass 1 to fix issues newly created
	read_data_blocks(partition, 2, 2, inode.pointers_data_block, 1, 1, 2);

	//Pass 3
	read_data_blocks(partition, 2, 2, inode.pointers_data_block, 3, 1, 2);
	for(i=1; i<=super_block.s_inodes_count; i++) {
		inode_data in = read_inode(partition, i);
		if(inode_link_count[i] != in.no_hard_links) {
			if(in.file_type != 0)
				printf("Inode %d (type: 0x%x) is not correct bro! Actual value:%d, collected_value:%d\n", i, in.file_type, in.no_hard_links, inode_link_count[i]);
				update_hard_link_counter(partition, i, inode_link_count[i]);
		}
	}


	//Pass 4
	printf("running pass 4 bro! %d\n", super_block.s_blocks_count);
	read_data_blocks(partition, 2, 2, inode.pointers_data_block, 4, 1, 2);
	printf("done with this shit! %d and %d\n", block_map[15072], check_block_bitmap(partition, 15072));
	for(i=1; i<=super_block.s_blocks_count; i++) {
        unsigned int bitmap_value = check_block_bitmap(partition, i);
		//printf("bitmap value:%d, collected_value:%d\n", bitmap_value, block_map[i]);
		/*if(block_map[i] == 1) {
			printf("Am I even doing this right!? %d\n", i);
		}*/
        if(block_map[i] == 1 && bitmap_value != block_map[i]) {
            //inode_data in = read_inode(partition, i);
               // printf("Inode %d (type: 0x%x) is not correct bro! bitmap value:%d, collected_value:%d\n", i, in.file_type, bitmap_value, inode_map[i]);
                /*if(in.file_type && 0x8000 == 0)
                    update_inode_entry_to_file(partition, i);*/
                //write_inode_entry(partition, i);
			printf("Block: %d bitmap value:%d, collected_value:%d\n", i, bitmap_value, block_map[i]);
			set_block_bitmap(partition, i, 1);
        }
    }
	/*inode_data temp_i = read_inode(partition, 32);
	printf("\n\n %d, %x, %d, %d\n", temp_i.inode_no, temp_i.file_type, temp_i.file_length, temp_i.pointers_data_block[0]);	*/
	printf("------------------------\n");
		
	//lions inode data block
	//inode_data lions_inode = read_inode(partition, 4017);
	//scan_dir_data_block(partition, lions_inode.pointers_data_block[0]);

	printf("------------------------------------\n");
	//unsigned int j;
	//inode_data in = read_inode(partition, 4021);
	/*char file_name[in.file_length];
	i = 0;
	for(j=0;j<in.file_length;j+=4) {
    	file_name[j+3]=in.pointers_data_block[i]>>24&0xFF;
		file_name[j+2]=in.pointers_data_block[i]>>16&0xFF;
		file_name[j+1]=in.pointers_data_block[i]>>8&0xFF;
		file_name[j]=in.pointers_data_block[i]&0xFF;
		i++;
    }
	file_name[j] = '\0';
	printf("filename: %s\n", file_name);*/
	//printf("\n\n File length: %d, File type: %02x, No of data blocks: %d\n", in.file_length, in.file_type, in.no_data_blocks);
	/*for(i=0;i<15;i++) {
		printf("Data block (Sector number), value in bitmap: %d (%d), %d\n", in.pointers_data_block[i], get_block_sector(partition, in.pointers_data_block[i]), check_block_bitmap(partition, in.pointers_data_block[i]));
	}*/
	//printf("Data block count: %d\n", get_data_block_count(partition, in.pointers_data_block));
}



/****************************************************************/

int main (int argc, char **argv)
{
	int opt;	
	int partition_no = -1;
	int fix_partition_no = -1;
	char *disk_image;
	//Check if number of arguments is 5
	if(argc < 5) {
		printf("Incorrect number of arguments. Usage:  ./myfsck -p <partition number> -i </path/to/disk/image>\n");
		exit(EX_USAGE);
	}
	//Read command line arguments
	while ((opt = getopt(argc, argv, "p:i:f:")) != -1) {
    	switch (opt)
	    {
    		case 'p':
        		partition_no = atoi(optarg);
		        break;
			case 'f':
				fix_partition_no = atoi(optarg);
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

	if(fix_partition_no != -1 && fix_partition_no != 0) {
		partition_entry *partition = get_partition_entry(entry, fix_partition_no);
		read_superblock(partition);
		read_root_inode(partition);
	}
	else if(fix_partition_no == 0) {
		partition_entry *temp = entry;
		while(temp != NULL) {
			printf("%02x, %d\n", temp->type, (temp->type == 0x83));
			if(temp->type == 0x83) {
				read_superblock(temp);
		        read_root_inode(temp);
			}
			memset(inode_map, 0, 100000);
			memset(inode_link_count, 0, 100000);
			memset(block_map, 0, 100000);
			temp = temp->next;
		}
	}

	//printf("start_sector = %d\n", entry->next->next->next->next->next->start_sector);
	//Read superblock
	//read_superblock(entry);
	//read_superblock(entry->next->next);
	//read_superblock(entry->next->next->next->next->next);

	//inode_data temp_i = read_inode(entry->next->next->next->next->next, 11);
	//printf("\n\n %d, %x, %d, %d\n", temp_i.inode_no, temp_i.file_type, temp_i.file_length, temp_i.pointers_data_block[0]);
	//printf("Checking inode bitmap: %d\n", check_inode_bitmap(entry, 100));
	//Read root inode
	//read_root_inode(entry);
	//read_root_inode(entry);
	//read_root_inode(entry->next->next);
	//printf("lost+found inode %d\n", lost_found_inode);
	//read_root_inode(entry->next->next);
	//read_root_inode(entry->next->next->next->next->next);
	//read_root_inode(entry->next->next->next->next->next);
	close(device);
	return 0;
}

/* EOF */
