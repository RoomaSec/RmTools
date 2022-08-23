/*
   Yara Rule Set
   Author: Colin Cowie
   Date: 2018-09-13
   Identifier: APT 10 (MenuPass)
   Reference: https://www.us-cert.gov/ncas/alerts/TA17-117A
*/

/* Rule Set ----------------------------------------------------------------- */


rule Maldoc_APT10_MenuPass {
   meta:
      description = "Detects APT10 MenuPass Phishing"
      author = "Colin Cowie"
      reference = "https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html"
      date = "2018-09-13"
   strings:
      $s1 = "C:\\ProgramData\\padre1.txt"
      $s2 = "C:\\ProgramData\\padre2.txt"
      $s3 = "C:\\ProgramData\\padre3.txt"
      $s5 = "C:\\ProgramData\\libcurl.txt"
      $s6 = "C:\\ProgramData\\3F2E3AB9"
   condition:
      any of them
}
