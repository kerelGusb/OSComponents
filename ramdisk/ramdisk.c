
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/vmalloc.h>

MODULE_DESCRIPTION("Simple RAM Disk");
MODULE_AUTHOR("SO2");
MODULE_LICENSE("GPL");


#define KERN_LOG_LEVEL		KERN_ALERT

#define MY_BLOCK_MAJOR		240
#define MY_BLKDEV_NAME		"mybdev"
#define KERNEL_SECTOR_SIZE	512


// define module param
static int nr_sectors = 131072;
module_param(nr_sectors, int, 0644);
MODULE_PARM_DESC(nr_sectors, "Number of sectors in ramdisk");


static struct my_block_dev {
	struct blk_mq_tag_set tag_set;
	struct gendisk *gd;
	u8 *data;
	size_t size;
} g_dev;

struct queue_limits lim = {
    .logical_block_size = KERNEL_SECTOR_SIZE,
    .physical_block_size = KERNEL_SECTOR_SIZE,
    .max_hw_sectors      = 256,
    .max_sectors         = 256,
    .max_segment_size    = 65536,
    .max_segments        = 128,
};

static int my_block_open(struct gendisk *disk, blk_mode_t mode)
{
    return 0;
}

static void my_block_release(struct gendisk *disk)
{
}

static const struct block_device_operations my_block_ops = {
	.owner = THIS_MODULE,
	.open = my_block_open,
	.release = my_block_release
};


static blk_status_t my_block_request(struct blk_mq_hw_ctx *hctx,
				     const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;

    struct gendisk *gd = rq->q->disk;
    struct my_block_dev *dev = gd->private_data;

	/* TODO 2: start request processing. */
	blk_mq_start_request(rq);

	/* TODO 2/5: check fs request. Return if passthrough. */
	if (blk_rq_is_passthrough(rq)) {
		printk(KERN_NOTICE "Skip non-fs request\n");
		blk_mq_end_request(rq, BLK_STS_IOERR);
		goto out;
	}

	/* TODO 2/6: print request information */
	printk(KERN_LOG_LEVEL
		"request received: pos=%llu bytes=%u "
		"cur_bytes=%u dir=%c\n",
		(unsigned long long) blk_rq_pos(rq),
		blk_rq_bytes(rq), blk_rq_cur_bytes(rq),
		rq_data_dir(rq) ? 'W' : 'R');

    struct bio_vec bvec;
	struct req_iterator iter;

	rq_for_each_segment(bvec, rq, iter) {
		sector_t sector = iter.iter.bi_sector;
		unsigned long offset = sector * KERNEL_SECTOR_SIZE;
		size_t len = bvec.bv_len;
		int dir = rq_data_dir(rq);
		char *buffer = kmap_local_page(bvec.bv_page) + bvec.bv_offset;
		printk(KERN_LOG_LEVEL "%s: buf %8p offset %lu len %u dir %d\n", __func__, buffer, offset, len, dir);

        /* check for read/write beyond end of block device */
        if ((offset + len) > dev->size) {
		    printk(KERN_ERR "request: read/write beyond end of block device\n");
            kunmap_local(buffer - bvec.bv_offset); 
            blk_mq_end_request(rq, BLK_STS_IOERR);
            goto out;
        }

        /* TODO 3/4: read/write to dev buffer depending on dir */
        if (dir == 1)		/* write */
            memcpy(dev->data + offset, buffer, len);
        else
            memcpy(buffer, dev->data + offset, len);

		kunmap_local(buffer - bvec.bv_offset);
	}

	blk_mq_end_request(rq, BLK_STS_OK);

out:
	return BLK_STS_OK;
}

static struct blk_mq_ops my_queue_ops = {
	.queue_rq = my_block_request,
};

static int create_block_device(struct my_block_dev *dev)
{
	int err;

	dev->size = nr_sectors * KERNEL_SECTOR_SIZE;

	dev->data = vmalloc(dev->size);
	if (dev->data == NULL) {
		printk(KERN_ERR "vmalloc: out of memory\n");
		err = -ENOMEM;
		goto out_vmalloc;
	}

	/* Initialize tag set. */
	dev->tag_set.ops = &my_queue_ops;
	dev->tag_set.nr_hw_queues = 1;
	dev->tag_set.queue_depth = 128;
	dev->tag_set.numa_node = NUMA_NO_NODE;
	dev->tag_set.cmd_size = 0;
	dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;

	err = blk_mq_alloc_tag_set(&dev->tag_set);
	if (err) {
	    printk(KERN_ERR "blk_mq_alloc_tag_set: can't allocate tag set\n");
	    goto out_alloc_tag_set;
	}

	/* initialize the gendisk structure */
	dev->gd = blk_mq_alloc_disk(&dev->tag_set, NULL, dev);
	if (IS_ERR(dev->gd)) {
		printk(KERN_ERR "alloc_disk: failure\n");
		err = PTR_ERR(dev->gd);
		goto out_blk_alloc_disk;
	} 

	dev->gd->major = MY_BLOCK_MAJOR;
	dev->gd->first_minor = 0;
    dev->gd->minors = 1;
	dev->gd->fops = &my_block_ops;
	dev->gd->private_data = dev;

	snprintf(dev->gd->disk_name, DISK_NAME_LEN, "myblock");
	set_capacity(dev->gd, nr_sectors);

	err = add_disk(dev->gd);
    if (err) {
        printk(KERN_ERR "add_disk: failure\n");
        goto out_put_disk;
    }

	return 0;

out_put_disk:
    put_disk(dev->gd);
out_blk_alloc_disk:
	blk_mq_free_tag_set(&dev->tag_set);
out_alloc_tag_set:
	vfree(dev->data);
out_vmalloc:
	return err;
}

static int __init my_block_init(void)
{
	int err = 0;

	/* TODO 1/5: register block device */
	err = register_blkdev(MY_BLOCK_MAJOR, MY_BLKDEV_NAME);
	if (err < 0) {
		printk(KERN_ERR "register_blkdev: unable to register\n");
		return err;
	}

	/* TODO 2/3: create block device using create_block_device */
	err = create_block_device(&g_dev);
	if (err < 0)
		goto out;

	return 0;

out:
	/* TODO 2/1: unregister block device in case of an error */
	unregister_blkdev(MY_BLOCK_MAJOR, MY_BLKDEV_NAME);
	return err;
}

static void delete_block_device(struct my_block_dev *dev)
{
	if (dev->gd) {
		del_gendisk(dev->gd);
		put_disk(dev->gd);
	}

    if (dev->tag_set.tags)
		blk_mq_free_tag_set(&dev->tag_set);

	if (dev->data)
		vfree(dev->data);
}

static void __exit my_block_exit(void)
{
	/* TODO 2/1: cleanup block device using delete_block_device */
	delete_block_device(&g_dev);

	/* TODO 1/1: unregister block device */
	unregister_blkdev(MY_BLOCK_MAJOR, MY_BLKDEV_NAME);
}

module_init(my_block_init);
module_exit(my_block_exit);