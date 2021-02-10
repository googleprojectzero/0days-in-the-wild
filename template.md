# 0-day Root Cause Analysis Template


# \<CVE\>: \<Description/Title\>
*Author*

## The Basics

**Disclosure or Patch Date:**

**Product:**

**Advisory:**

**Affected Versions:**

**First Patched Version:**

**Issue/Bug Report:**

**Patch CL:**

**Bug-Introducing CL:**

**Reporter(s):** 

## The Code

**Proof-of-concept:**

**Exploit sample:**

**Access to the exploit sample?** *(Did you have access to the exploit sample when doing the analysis?)*


## The Vulnerability

**Bug class:**

**Vulnerability details:**

**Patch analysis:**

**Thoughts on how this vuln might have been found _(fuzzing, code auditing, variant analysis, etc.)_:**

**(Historical/present/future) context of bug:** 

## The Exploit

(The terms *exploit primitive*, *exploit strategy*, *exploit technique*, and *exploit flow* are [defined here](https://googleprojectzero.blogspot.com/2020/06/a-survey-of-recent-ios-kernel-exploits.html).)

**Exploit strategy (or strategies):** 

**Exploit flow:** 

**Known cases of the same exploit flow:**

**Part of an exploit chain?**

## The Next Steps

### Variant analysis

**Areas/approach for variant analysis (and why):**

**Found variants:**

### Structural improvements

What are structural improvements such as ways to kill the bug class, prevent the introduction of this vulnerability, mitigate the exploit flow, make this type of vulnerability harder to exploit, etc.?

**Ideas to kill the bug class:**

**Ideas to mitigate the exploit flow:**

**Other potential improvements:**

### 0-day detection methods

What are potential detection methods for similar 0-days? Meaning are there any ideas of how this exploit or similar exploits could be detected **as a 0-day**?

## Other References 
