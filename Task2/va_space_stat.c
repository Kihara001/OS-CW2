#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/pid.h>

struct addr_space_info {
    unsigned long num_vmas;
    unsigned long num_anon;
    unsigned long num_file;
    unsigned long num_w_and_x;
    unsigned long total_mapped;
    unsigned long total_resident;
    unsigned long largest_gap;
    unsigned long stack_size;
    unsigned long heap_size;
};

static unsigned long count_resident_pages(struct mm_struct *mm,
                                          struct vm_area_struct *vma)
{
    unsigned long addr;
    unsigned long resident = 0;

    for (addr = vma->vm_start; addr < vma->vm_end; addr += PAGE_SIZE) {
        pgd_t *pgd;
        p4d_t *p4d;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;

        pgd = pgd_offset(mm, addr);
        if (pgd_none(*pgd) || pgd_bad(*pgd))
            continue;

        p4d = p4d_offset(pgd, addr);
        if (p4d_none(*p4d) || p4d_bad(*p4d))
            continue;

        pud = pud_offset(p4d, addr);
        if (pud_none(*pud) || pud_bad(*pud))
            continue;

        pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd) || pmd_bad(*pmd))
            continue;

        pte = pte_offset_kernel(pmd, addr);
        if (pte_none(*pte))
            continue;

        if (pte_present(*pte))
            resident++;
    }

    return resident;
}

SYSCALL_DEFINE2(va_space_stat, pid_t, pid,
                struct addr_space_info __user *, info)
{
    struct addr_space_info kinfo = {0};
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned long prev_end = 0;
    
    // 1. エラーチェック
    if (pid < 0)
        return -EINVAL;
    
    // 2. プロセス取得
    if (pid == 0) {
        task = current;
        get_task_struct(task);
    } else {
        task = find_get_task_by_vpid(pid);
        if (!task)
            return -ESRCH;
    }
    
    // 3. mm取得
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return -EINVAL;
    
    // 4. mmをロック
    mmap_read_lock(mm);
    
    // 5. VMAをイテレート
    VMA_ITERATOR(vmi, mm, 0);
    for_each_vma(vmi, vma) {
        // num_vmas
        kinfo.num_vmas++;
        
        // num_anon / num_file
        if (vma->vm_file)
            kinfo.num_file++;
        else
            kinfo.num_anon++;
        
        // num_w_and_x
        if ((vma->vm_flags & VM_WRITE) && (vma->vm_flags & VM_EXEC))
            kinfo.num_w_and_x++;
        
        // total_mapped
        kinfo.total_mapped += vma->vm_end - vma->vm_start;
        
        // largest_gap
        if (prev_end != 0 && vma->vm_start > prev_end) {
            unsigned long gap = vma->vm_start - prev_end;
            if (gap > kinfo.largest_gap)
                kinfo.largest_gap = gap;
        }
        prev_end = vma->vm_end;
        
        // stack_size
        if (vma->vm_start <= mm->start_stack && mm->start_stack < vma->vm_end)
            kinfo.stack_size = vma->vm_end - vma->vm_start;
        
        // total_resident (ページテーブルウォーク)
        kinfo.total_resident += count_resident_pages(mm, vma);
        // TODO: 各ページのPTEを確認してカウント
    }
    
    // 6. heap_size
    kinfo.heap_size = mm->brk - mm->start_brk;
    
    // 7. ロック解除
    mmap_read_unlock(mm);
    mmput(mm);
    
    // 8. ユーザー空間にコピー
    if (copy_to_user(info, &kinfo, sizeof(kinfo)))
        return -EFAULT;
    
    return 0;
}