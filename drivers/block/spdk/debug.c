#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/rcupdate.h>
#include <linux/fdtable.h>


static char path_buf[256];

void spdk_dump_all_files(void) {
    struct task_struct *p;
    unsigned int fd;
    struct files_struct *files;
    struct file *fd_file;

    rcu_read_lock();
    for_each_process(p) {
        files = get_files_struct(p);
        spin_lock(&files->file_lock);
        for (fd = 0; fd < files_fdtable(files)->max_fds; fd++) {
            fd_file = fcheck_files(files, fd);
            if (fd_file) {
                char *path = d_path(&fd_file->f_path, path_buf, sizeof(path_buf));
                if (IS_ERR(path)) {
                    printk("fd: %d: comm: %s\n", fd, p->comm);
                } else {
                    printk("fd: %d: comm: %s path %s\n", fd, p->comm, path);
                }
            }
        }
        spin_unlock(&files->file_lock);
        put_files_struct(files);
    }
    rcu_read_unlock();
}
