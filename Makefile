
all:
	gcc -W fsck.c -o myfsck

clean:
	rm myfsck
	rm myfsck.tar

tar:
	tar cf myfsck.tar fsck.c ext2_fs.h genhd.h Makefile

