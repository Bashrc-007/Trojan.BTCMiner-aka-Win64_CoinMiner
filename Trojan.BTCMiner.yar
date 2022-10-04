/*
   YARA Rule Set
   Date: 2021-06-01
   File: eguikrnoxye.exe

*/

/* Rule Set ----------------------------------------------------------------- */

rule eguikrnoxye {
   meta:
      description = "file eguikrnoxye.exe"
      date = "2021-06-01"
      hash1 = "a2b04904e1a1ca40dea1c8940f01ebdfdbf8f8f4827f4e91e6c9a63301cd7d0d"
   strings:
      $s1 = "API bind to port %d failed - trying again in 20sec" fullword ascii
      $s2 = "API: exec command %s(%s)" fullword ascii
      $s3 = "invalid username:password pair -- '%s'" fullword ascii
      $s4 = "WinRing0x64.sys" fullword wide
      $s5 = "Huge Pages: Failed to open process token." fullword ascii
      $s6 = "%s: unsupported non-option argument -- '%s'" fullword ascii
      $s7 = "libcrypto-1_1-x64.dll" fullword ascii
      $s8 = "  -x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy" fullword ascii
      $s9 = "getblocktemplate failed, falling back to getwork" fullword ascii
      $s10 = "API: connection from %s - %s" fullword ascii
      $s11 = "      --no-gbt          disable getblocktemplate support" fullword ascii
      $s12 = "hash > target (false positive)" fullword ascii
      $s13 = "hash <= target" fullword ascii
      $s14 = "  -P, --protocol-dump   verbose dump of protocol-level activities" fullword ascii
      $s15 = "verthash.dat" fullword ascii
      $s16 = "Failed to start WinRing0 driver: WinRing0x64.sys not found" fullword ascii
      $s17 = "User-Agent: cpuminer-opt-gr/1.1.5" fullword ascii
      $s18 = "Testing Cryptonigh --cn-config %d,%d,%d,%d,%d,%d" fullword ascii
      $s19 = "NAME=%s;VER=%s;API=%s;ALGO=%s;CPUS=%d;URL=%s;HS=%.2f;KHS=%.2f;ACC=%d;REJ=%d;SOL=%d;ACCMN=%.3f;DIFF=%s;TEMP=%.1f;FAN=%d;FREQ=%d;U" ascii
      $s20 = "Best --cn-config %d,%d,%d,%d,%d,%d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

