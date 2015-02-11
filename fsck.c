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

#if defined(__FreeBSD__)
#define lseek64 lseek
#endif

/* linux: lseek64 declaration needed here to eliminate compiler warning. */
extern int64_t lseek64(int, int64_t, int);

const unsigned int sector_size_bytes = 512;

const unsigned int partition_record_size = 16;

static int device;  /* disk file descriptor */

static int ebr_offset = 0;

typedef struct partition_entry {
	unsigned int partition_no;
	unsigned int type;
	unsigned int start_sector;
	unsigned int length;
	struct partition_entry *next;
}partition_entry;

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
    int i;
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
	int partition_addr, i;
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
		while(entry->next != NULL)
			entry = entry->next;
		temp = temp->next;
	}
	
	return first;
}


int main (int argc, char **argv)
{
	int opt;	
	int partition_no;
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
	close(device);

	int count = 1;
	while(entry != NULL) {
		if(partition_no == count) {
			printf("0x%02X %d %d\n", entry->type, entry->start_sector, entry->length);
			return 0;
		}
		entry = entry->next;
		count++;
	}
	printf("-1\n");
    return EX_DATAERR;
}

/* EOF */
