# CVE-2023-33107: Qualcomm Adreno GPU KGSL_IOCTL_GPUOBJ_IMPORT integer overflow
*Benoît Sevens and Jann Horn*

## The Basics

**Disclosure or Patch Date:** October 2, 2023

**Product:** Qualcomm Adreno GPU

**Advisory:** https://docs.qualcomm.com/product/publicresources/securitybulletin/october-2023-bulletin.html

**Affected Versions:** N/A

**First Patched Version:** N/A

**Issue/Bug Report:** N/A

**Patch CL:** https://git.codelinaro.org/clo/la/kernel/msm-4.19/-/commit/d66b799c804083ea5226cfffac6d6c4e7ad4968b

**Bug-Introducing CL:** N/A

**Reporter(s):** Jann Horn of Google's Project Zero and Benoît Sevens of Google's Threat Analysis Group

## The Code

**Proof-of-concept:** Not public

**Exploit sample:** Not public

**Did you have access to the exploit sample when doing the analysis?** Yes

## The Vulnerability

**Bug class:** Integer overflow

**Vulnerability details:**

(Analysis was performed at the 1f0f7f32382465b374864ad5b0fb2c02ceb3ba07 commit of https://android.googlesource.com/kernel/msm)

When `kgsl_ioctl_gpuobj_import()` is called with type `KGSL_USER_MEM_TYPE_ADDR`, we can have this call sequence:

```
kgsl_ioctl_gpuobj_import
  _gpuobj_map_useraddr
    kgsl_setup_useraddr
      kgsl_setup_anon_useraddr
        kgsl_mmu_set_svm_region
          kgsl_iommu_set_svm_region
            [Check for overlap in region to be added]
            _insert_gpuaddr
      memdesc_sg_virt
        kvcalloc
      kgsl_mmu_put_gpuaddr
        kgsl_iommu_put_gpuaddr
          _remove_gpuaddr
            rb_erase
```

In `kgsl_iommu_set_svm_region()`, if no overlap is detected, `_insert_gpuaddr()` will insert the user space provided address and size in the red-black tree `pagetable->priv->rbtree` that tracks the IOMMU mapped ranges [1]. `iommu_addr_in_svm_ranges()` [2] only checks if the start and end address are within the SVM range, but doesn’t check if the end is smaller than the start (by wrapping around).

```c
static int kgsl_iommu_set_svm_region(struct kgsl_pagetable *pagetable,
                uint64_t gpuaddr, uint64_t size)
{
        int ret = -ENOMEM;
        struct kgsl_iommu_pt *pt = pagetable->priv;
        struct rb_node *node;

        /* Make sure the requested address doesn't fall out of SVM range */
        if (!iommu_addr_in_svm_ranges(pt, gpuaddr, size))  // *** [2] ***
                return -ENOMEM;

        spin_lock(&pagetable->lock);
        node = pt->rbtree.rb_node;

        while (node != NULL) {
                uint64_t start, end;
                struct kgsl_iommu_addr_entry *entry = rb_entry(node,
                        struct kgsl_iommu_addr_entry, node);
        
                start = entry->base;
                end = entry->base + entry->size;
        
                if (gpuaddr  + size <= start)  // *** [3] ****
                        node = node->rb_left;
                else if (end <= gpuaddr)
                        node = node->rb_right;
                else
                        goto out;
        }

        ret = _insert_gpuaddr(pagetable, gpuaddr, size);  // *** [1] ***
out:
        spin_unlock(&pagetable->lock);
        return ret;
}
```

The integer overflow is in `kgsl_iommu_set_svm_region()` when performing the overlap check. User space can set the values of `kgsl_gpuobj_import.priv` (local variable `gpuaddr`) and `kgsl_gpuobj_import.priv_len` (local variable `size`) such that when they are added in `kgsl_iommu_set_svm_region()` [3], an integer overflow occurs, wrapping around the address space such that the end is less than the start.

This leads to a short lived bogus entry in the rbtree. `kgsl_setup_anon_useraddr()` will later on (when `kvcalloc()` in `memdesc_sg_virt()` failed) delete that entry in `rb_erase()`.

However a racing thread could perform an `mmap()` on an overlapping region while the rbtree still contains the invalid entry, which can lead to not detecting the overlap because of the bogus entry. This can lead to IOMMU page tables entries being wrongly deleted and ultimately to dangling IOMMU PTE's (see the "Exploit flow" section below for details).

Note that a different ioctl `kgsl_ioctl_map_user_mem()` with memtype `KGSL_MEM_ENTRY_USER` can also be used to reach `kgsl_iommu_set_svm_region()` in a similar way.

```
kgsl_ioctl_map_user_mem
  _map_usermem_addr
    kgsl_setup_useraddr
      kgsl_mmu_set_svm_region
        kgsl_iommu_set_svm_region
          [Check for overlap in region to be added]
          _insert_gpuaddr
```

**Patch analysis:**

```c
diff --git a/drivers/gpu/msm/kgsl_iommu.c b/drivers/gpu/msm/kgsl_iommu.c
index e4b9924baec205838223078a4537da3d4bfcbf23..c54f6edaf6fc008d4756c244bc8d69438390b4c3 100644
--- a/drivers/gpu/msm/kgsl_iommu.c
+++ b/drivers/gpu/msm/kgsl_iommu.c
@@ -1,7 +1,7 @@
 // SPDX-License-Identifier: GPL-2.0-only
 /*
  * Copyright (c) 2011-2021, The Linux Foundation. All rights reserved.
- * Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.
+ * Copyright (c) 2022-2023, Qualcomm Innovation Center, Inc. All rights reserved.
  */
 
 #include <linux/compat.h>
@@ -2428,14 +2428,18 @@ static uint64_t kgsl_iommu_find_svm_region(struct kgsl_pagetable *pagetable,
 static bool iommu_addr_in_svm_ranges(struct kgsl_iommu_pt *pt,
 	u64 gpuaddr, u64 size)
 {
+	u64 end = gpuaddr + size;
+
+	/* Make sure size is not zero and we don't wrap around */
+	if (end <= gpuaddr)  // *** [4] ***
+		return false;
+
 	if ((gpuaddr >= pt->compat_va_start && gpuaddr < pt->compat_va_end) &&
-		((gpuaddr + size) > pt->compat_va_start &&
-			(gpuaddr + size) <= pt->compat_va_end))
+		(end > pt->compat_va_start && end <= pt->compat_va_end))
 		return true;
 
 	if ((gpuaddr >= pt->svm_start && gpuaddr < pt->svm_end) &&
-		((gpuaddr + size) > pt->svm_start &&
-			(gpuaddr + size) <= pt->svm_end))
+		(end > pt->svm_start && end <= pt->svm_end))
 		return true;
 
 	return false;
```

Apart from some variable refactoring, the patch introduces a check in `iommu_addr_in_svm_ranges()` that makes sure the range does not wrap around [4].

A second related [patch](https://git.codelinaro.org/clo/la/kernel/msm-4.19/-/commit/de59b74d74c7b523b116cf1149a1111ceb56f6a0) was published that checks the return value of `arm_lpae_init_pte()`. This patch breaks the exploit's current technique as explained in the "Exploit flow" section.

**Thoughts on how this vuln might have been found _(fuzzing, code auditing, variant analysis, etc.)_:**

`iommu_addr_in_svm_ranges()` was introduced in the [fix](https://git.codelinaro.org/clo/la/kernel/msm-4.19/-/commit/b8d6a6665e15224b6913c48ac6641d6a9f42db61) for [CVE-2020-11261](https://source.android.com/docs/security/bulletin/2021-01-01), which was reported by Man Yue Mo but also exploited in the wild. CVE-2023-33107 could have been found by analyzing the patch for CVE-2020-11261 and auditing the same code area for variants. 

**(Historical/present/future) context of bug:** N/A

## The Exploit

(The terms *exploit primitive*, *exploit strategy*, *exploit technique*, and *exploit flow* are [defined here](https://googleprojectzero.blogspot.com/2020/06/a-survey-of-recent-ios-kernel-exploits.html).)

**Exploit strategy (or strategies):**

* Groom the right rbtree, which amongst others contains a "UAF" range
* Using a race:
  * Insert a "BOGUS" range in the rbtree that has an end address that wraps around.
  * Insert an "OVERLAP" range in the rbtree that overlaps with the "UAF" range.
    * A side effect is that the first IOMMU PTE of the UAF range is deleted.
* Free the UAF range. Since its first IOMMU PTE is zero, other IOMMU PTE's are not touched. The physical pages however are freed.
* Trigger shrinking to return the freed KGSL pages to the normal kernel page allocator.
* Spray new tasks, such that at least one of their `task_struct`'s falls in previously freed pages.
* Using GPU commands we can still read and write (via the IOMMU PTE) to these pages:
  * Scan the pages to find one of these `task_struct`'s.
  * Overwrite the `addr_limit` field of that `task_struct` with `KERNEL_DS`.

**Exploit flow:**

(The described exploit flow is based on a proof of concept written by Jann Horn.)

The exploit uses the following 4 ranges shared between user space and the GPU, which we will summarize first for clarity:

```
OVERLAP:        0x7001fe000 -> 0x700205000 (size: 0x7000)
UAF:            0x7001ff000 -> 0x710203000 (size: 0x10004000)
BOGUS:          0x700204000 -> 0x700101000 (size: 0xffffffffffefd000)
PLACEHOLDER:    0x710204000 -> 0x720604000 (size: 0x10400000)
```

##### Setting up the right rbtree

We allocate memory for the `UAF` and `OVERLAP` objects (via `IOCTL_KGSL_GPUOBJ_ALLOC`) and `mmap()` the `UAF` object. This will set up the page table entries (PTE) for the MMU and IOMMU. The rbtree in the `kgsl_iommu_pt`structure, which tracks the IOMMU page table mappings, looks like:

```
name                  start        end          color
UAF                   0x7001ff000  0x710203000  black
```

To hit the right code path later, we need to map an anonymous VMA at the start address of the `BOGUS` object (`0x700204000`). However we currently have the `UAF` object mapped there, which we need to unmap first. Fortunately, `munmap()`'ing that object will not remove the rbtree entry and remove the IOMMU page table entries until explicitly freed.

After unmapping the `UAF` object, we `mmap()` a small anonymous map at the start address of the `BOGUS` range.

Next we allocate memory for the `PLACEHOLDER` object and `mmap()` it. The rbtree now becomes:

```
name                     start        end          color
UAF                      0x7001ff000  0x710203000  black   [START] [walk right]
 \-[right]- PLACEHOLDER  0x710204000  0x720604000  red
```

##### Race to insert an overlapping range in the rbtree

In a racing thread, we now call `IOCTL_KGSL_MAP_USER_MEM` with the start address of `BOGUS` and its huge length (that wraps around the end address). Because of the vulnerability, this `BOGUS` entry is not detected as invalid in `iommu_addr_in_svm_ranges` or as overlapping in `kgsl_iommu_set_svm_region()`: 

```
name                     start        end          color
UAF                      0x7001ff000  0x710203000  black   [START] [walk left, nothing found]
 \-[right]- PLACEHOLDER  0x710204000  0x720604000  red
```

Note that `_insert_gpuaddr()` then just reasons on the starting addresses of the entries to decide where to insert the new entry in the tree. The rbtree becomes:

```
name                                  start        end          color
UAF                                   0x7001ff000  0x710203000  black   [START] [walk right]
 \             /-[left] BOGUS         0x700204000  0x700101000  red    
  \-[right] PLACEHOLDER               0x710204000  0x720604000  red     [walk left]
```

The rbtree will now get rebalanced (refer to `__rb_insert()` for the details) to:

```
name                                  start        end          color
 /-[left] UAF                         0x7001ff000  0x710203000  red
BOGUS                                 0x700204000  0x700101000  black
 \-[right] PLACEHOLDER                0x710204000  0x720604000  red
```

At this point, in the main thread, we perform a `mmap()` on the `OVERLAP` object. The relevant calls are:

```
do_mmap
  kgsl_get_unmapped_area
    _get_svm_area
      _gpu_set_svm_region
        kgsl_mmu_set_svm_region
          kgsl_iommu_set_svm_region
            [Check for overlap in region to be added]
            _insert_gpuaddr
        kgsl_mmu_map
          kgsl_iommu_map
            iommu_map_sg
              arm_smmu_map_sg
                arm_lpae_map_sg  // *** [5] ***
                arm_smmu_unmap  // *** [8] ***
```

Normally this should fail with `ENOMEM` in `kgsl_iommu_set_svm_region()` because of the conflicting `UAF` object mapping. However, because of the `BOGUS` entry, the lookup in `kgsl_iommu_set_svm_region()` goes like:

```
name                                  start        end          color
 /-[left] UAF                         0x7001ff000  0x710203000  red
BOGUS                                 0x700204000  0x700101000  black  [START] [walk right]
 \-[right] PLACEHOLDER                0x710204000  0x720604000  red    [walk left, nothing found]
```

`_insert_gpuaddr()` will then insert the `OVERLAP` object purely based on the start address of the ranges. We obtain:

```
           /-[left] OVERLAP           0x7001fe000  0x700205000  red
 /-[left] UAF                         0x7001ff000  0x710203000  red    [walk left]
BOGUS                                 0x700204000  0x700101000  black  [START] [walk left]
 \-[right] PLACEHOLDER                0x710204000  0x720604000  red
```

The rbtree will again be rebalanced, but this is not relevant for the exploit anymore, since we obtained an overlapping object in the tree.

Also, the `kgsl_ioctl_map_user_mem()` call in the racing thread will fail at some point, because of the huge `BOGUS` size (which will trigger a failed `kvcalloc()` in `memdesc_sg_virt()`). This will lead to the `BOGUS` entry being removed from the rbtree (in `kgsl_mmu_put_gpuaddr()`). However this does not affect overlapping ranges in the rbtree between `OVERLAP` and `UAF`.

##### Wrong PTE deletion as a consequence of the overlap

Continuing in the `mmap()` call on the `OVERLAP` object of the main thread, `arm_lpae_map_sg()` gets called later on [5].

```c
static int arm_lpae_map_sg(struct io_pgtable_ops *ops, unsigned long iova,
			   struct scatterlist *sg, unsigned int nents,
			   int iommu_prot, size_t *size)
{
    ...
			if (ms.pgtable && (iova < ms.iova_end)) {
				arm_lpae_iopte *ptep = ms.pgtable +
					ARM_LPAE_LVL_IDX(iova, MAP_STATE_LVL,
							 data);
				arm_lpae_init_pte(
					data, iova, phys, prot, MAP_STATE_LVL,
					ptep, ms.prev_pgtable, false);  // *** [6] ** 
				ms.num_pte++;  // *** [7] ***
			} else {
				ret = __arm_lpae_map(data, iova, phys, pgsize,
						prot, lvl, ptep, NULL, &ms);
				if (ret)
					goto out_err;
			}
    ...
}
```

`arm_lape_map_sg()` will:

* Call `__arm_lpae_map()` for address 0x7001fe000 and check its return value. This will set up a PTE for 0x7001fe000 without error.
* Call `arm_lpae_init_pte()` for address 0x7001ff000 without checking its return value. This will fail because of an existing PTE (of the `UAF` object), but the return value is not checked [6] and the number of mapped PTE's incremented [7].
* Call `__arm_lpae_map()` for address 0x700200000 and check its return value. This will fail because of an existing PTE and now we bail out.

In the bailout path, `arm_smmu_unmap()` [8] will remove the 2 PTE's at 0x7001fe000 and 0x7001ff000. This means we now delete the first PTE of the `UAF` object.

This is where the [second patch](https://git.codelinaro.org/clo/la/kernel/msm-4.19/-/commit/de59b74d74c7b523b116cf1149a1111ceb56f6a0) has its use: it now checks the return value of the `arm_lpae_init_pte()` and bails out on error without incrementing the number of mapped PTE's.

##### Create dangling IOMMU page table entries

If we now free the `UAF` object (via `IOCTL_KGSL_GPUOBJ_FREE`), the following relevant calls will be performed:

```
kgsl_ioctl_gpuobj_free
  kgsl_mem_entry_put_deferred
    kgsl_mem_entry_destroy_deferred
      _deferred_destroy
        mem_entry_destroy
          kgsl_mem_entry_detach_process
            kgsl_mmu_put_gpuaddr 
              kgsl_mmu_unmap
                kgsl_iommu_unmap 
                  kgsl_iommu_unmap_offset
                    _iommu_unmap_sync_pc
                      iommu_unmap
                        __iommu_unmap
                          arm_smmu_unmap
                            arm_lpae_unmap
                              __arm_lpae_unmap
```

`__arm_lpae_unmap()` will bail out when encountering the first zeroed PTE of address 0x7001ff000. This means the UAF object memory is freed but dangling IOMMU PTE's are not removed.

##### Exploit freed memory

To pass back the freed KGSL pages to the kernel page allocator, we invoke the shrinker. These pages can now be handed out by the kernel for other uses, while the GPU still has a read and write view on it.

We can now exploit these dangling IOMMU PTE's by sending commands to the GPU (via `IOCTL_KGSL_GPU_COMMAND`) to read and write to these pages. This means we can:

* Read these pages to find interesting kernel data, such as `task_struct`'s.
* Write to these pages to modify e.g. the `addr_limit` field of a `task_struct` of interest.

**Known cases of the same exploit flow:** N/A

**Part of an exploit chain?** N/A

## The Next Steps

### Variant analysis

**Areas/approach for variant analysis (and why):** N/A

**Found variants:** N/A

### Structural improvements

What are structural improvements such as ways to kill the bug class, prevent the introduction of this vulnerability, mitigate the exploit flow, make this type of vulnerability harder to exploit, etc.?

**Ideas to kill the bug class:** N/A

**Ideas to mitigate the exploit flow:** N/A

**Other potential improvements:** N/A

### 0-day detection methods

What are potential detection methods for similar 0-days? Meaning are there any ideas of how this exploit or similar exploits could be detected **as a 0-day**?

## Other References 

N/A