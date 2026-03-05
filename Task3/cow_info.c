

#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/mm_types.h>
#include <linux/pagewalk.h>
#include <linux/page_ref.h>
#include <asm/pgtable.h>

struct cow_info {
    unsigned long total_cow;
    unsigned long anon_cow;
    unsigned long file_cow;
    unsigned long total_writable;
    unsigned long num_cow_vmas;
    unsigned long cow_fault_count;
};

/* walk_page_vma用のデータ構造 */
struct cow_walk_data {
    unsigned long cow_count;
    unsigned long writable_count;
};

/* PTEエントリごとに呼ばれるコールバック */
static int cow_pte_entry(pte_t *pte, unsigned long addr,
                         unsigned long next, struct mm_walk *walk)
{
    struct cow_walk_data *data = walk->private;
    struct page *page;
    pte_t ptent = ptep_get(pte);

    /* presentでないページは無視 */
    if (!pte_present(ptent))
        return 0;

    /* writableなVMAのpresentページをカウント */
    data->writable_count++;

    /* write権限があればCOWではない */
    if (pte_write(ptent))
        return 0;

    /* ゼロページはCOWではない */
    if (is_zero_pfn(pte_pfn(ptent)))
        return 0;

    /* ページを取得 */
    page = pte_page(ptent);
    if (!page)
        return 0;

    /* 参照カウント > 1 = 共有されている = COW */
    if (page_count(page) > 1)
        data->cow_count++;

    return 0;
}

static const struct mm_walk_ops cow_walk_ops = {
    .pte_entry = cow_pte_entry,
    .walk_lock = PGWALK_RDLOCK,
};

SYSCALL_DEFINE2(cow_info, pid_t, pid,
                struct cow_info __user *, info)
{
    struct cow_info kinfo = {0};
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;

    if (pid < 0)
        return -EINVAL;

    /* プロセス取得 */
    if (pid == 0) {
        task = current;
        get_task_struct(task);
    } else {
        task = find_get_task_by_vpid(pid);
        if (!task)
            return -ESRCH;
    }

    /* mm取得 */
    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }

    /* cow_fault_countを読む */
    kinfo.cow_fault_count = atomic_long_read(&task->cow_fault_count);
    put_task_struct(task);

    /* VMAをイテレート */
    mmap_read_lock(mm);

    VMA_ITERATOR(vmi, mm, 0);
    for_each_vma(vmi, vma) {
        struct cow_walk_data data = {0};

        /* VM_WRITEなVMAのみ対象 */
        if (!(vma->vm_flags & VM_WRITE))
            continue;

        /* 効率的にページテーブルをwalk */
        walk_page_vma(vma, &cow_walk_ops, &data);

        kinfo.total_writable += data.writable_count;
        kinfo.total_cow += data.cow_count;

        if (data.cow_count > 0) {
            kinfo.num_cow_vmas++;
            if (vma->vm_file)
                kinfo.file_cow += data.cow_count;
            else
                kinfo.anon_cow += data.cow_count;
        }
    }

    mmap_read_unlock(mm);
    mmput(mm);

    if (copy_to_user(info, &kinfo, sizeof(kinfo)))
        return -EFAULT;

    return 0;
}