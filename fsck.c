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

#if defined(__FreeBSD__)
#define lseek64 lseek
#endif

/* linux: lseek64 declaration needed here to eliminate compiler warning. */
extern int64_t lseek64(int, int64_t, int);

const unsigned int sector_size_bytes = 512;

const unsigned int partition_record_size = 16;

static int device;  /* disk file descriptor */

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

    if (num_sectors == 1) {
        printf("Reading sector %"PRId64"\n", start_sector);
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
 * Given a partition entry, read it and extract required info
 */
void read_partition_entry(char *part_buf) {
	int type;	
	unsigned int start_sector, length;

	//Extract type
	type = (int)part_buf[4] & 0xFF;

	//Extract start address
	start_sector = ((int)part_buf[8] << 24) | ((int)part_buf[9] << 16) | ((int)part_buf[10] << 8) | ((int)part_buf[11]);

	//Extract end address
	length = ((int)part_buf[12] << 24) | ((int)part_buf[13] << 16) | ((int)part_buf[14] << 8) | ((int)part_buf[15]);

	printf("0x%02X %u %u\n", type, start_sector, length * sector_size_bytes);
}


int main (int argc, char **argv)
{
	int opt;	
	int partition_no;
	char *disk_image;
	//Check if number of arguments is 5
	if(argc < 5) {
		printf("Incorrect number of arguments. Usage:  ./myfsck -p <partition number> -i </path/to/disk/image>\n");
		exit(EXIT_FAILURE);
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
        		exit(EXIT_FAILURE);
    	}
	}
    
	unsigned char buf[sector_size_bytes];        /* temporary buffer */
	unsigned char part_buf[partition_record_size];
    int	the_sector;                     /* IN: sector to read */
	int partition_addr;	//Index of partition in buf
	int i;

    if ((device = open(disk_image, O_RDWR)) == -1) {
        perror("Could not open device file");
        exit(-1);
    }

	//Reading sector 0 for MBR
    the_sector = 0;
    //printf("Dumping sector %d:\n", the_sector);
    read_sectors(the_sector, 1, buf);

	//Partition 1
	partition_addr = 446 + (partition_no * 16);
	for(i = partition_addr; i < partition_addr + partition_record_size; i++) {
		part_buf[i-partition_addr] = buf[i];
		printf("%02x", buf[i]);
	}

	printf("\n");	
	read_partition_entry(part_buf);

	/*
	//Partition 2
    partition_addr = 462;
    for(i = partition_addr; i < partition_addr + 16; i++) {
        printf("%02x", buf[i]);
    }

	printf("\n");

	//Partition 3
    partition_addr = 478;
    for(i = partition_addr; i < partition_addr + 16; i++) {
        printf("%02x", buf[i]);
    }

	printf("\n");

	//Partition 4
    partition_addr = 494;
    for(i = partition_addr; i < partition_addr + 16; i++) {
        printf("%02x", buf[i]);
    }

	printf("\n");*/
    close(device);
    return 0;
}

/* EOF */
