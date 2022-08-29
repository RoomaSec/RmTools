rule miner_batch {
   meta:
      description = "file kit.bat"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/"
      date = "2022/07/10"
      hash1 = "4905b7776810dc60e710af96a7e54420aaa15467ef5909b260d9a9bc46911186"
   strings:
      $a1 = "%~dps0" fullword ascii
      $a2 = "set app" fullword ascii
      $a3 = "cd /d \"%~dps0\"" fullword ascii
      $a4 = "set usr=jood" fullword ascii
      $s1 = "schtasks /run" fullword ascii
      $s2 = "schtasks /delete" fullword ascii
      $a5 = "if \"%1\"==\"-s\" (" fullword ascii
   condition:
      uint16(0) == 0xfeff and filesize < 1KB and
      3 of ($a*) and 1 of ($s*)
}

rule file_ex_exe {
   meta:
      description = "files - file ex.exe.bin"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/"
      date = "2022/07/10"
      hash1 = "428d06c889b17d5f95f9df952fc13b1cdd8ef520c51e2abff2f9192aa78a4b24"
   strings:
      $s1 = "d:\\Projects\\WinRAR\\rar\\build\\unrar32\\Release\\UnRAR.pdb" fullword ascii
      $s2 = "rar.log" fullword wide
      $s3 = "      <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s4 = "  processorArchitecture=\"*\"" fullword ascii
      $s5 = "%c%c%c%c%c%c%c" fullword wide /* reversed goodware string 'c%c%c%c%c%c%c%' */
      $s6 = "  version=\"1.0.0.0\"" fullword ascii
      $s7 = "%12ls: RAR %ls(v%d) -m%d -md=%d%s" fullword wide
      $s8 = "  hp[password]  " fullword wide
      $s9 = " %s - " fullword wide
      $s10 = "yyyymmddhhmmss" fullword wide
      $s11 = "--------  %2d %s %d, " fullword wide
      $s12 = " Type Descriptor'" fullword ascii
      $s13 = "\\$\\3|$4" fullword ascii /* hex encoded string '4' */
      $s14 = "      processorArchitecture=\"*\"" fullword ascii
      $s15 = " constructor or from DllMain." fullword ascii
      $s16 = "----------- ---------  -------- -----  ----" fullword wide
      $s17 = "----------- ---------  -------- ----- -------- -----  --------  ----" fullword wide
      $s18 = "%-20s - " fullword wide
      $s19 = "      publicKeyToken=\"6595b64144ccf1df\"" fullword ascii
      $s20 = "      version=\"6.0.0.0\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule smss_exe {
   meta:
      description = "files - file smss.exe.bin"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/"
      date = "2022/07/10"
      hash1 = "d3c3f529a09203a839b41cd461cc561494b432d810041d71d41a66ee7d285d69"
   strings:
      $s1 = "mCFoCRYPT32.dll" fullword ascii
      $s2 = "gPSAPI.DLL" fullword ascii
      $s3 = "www.STAR.com" fullword wide
      $s4 = "4;#pMVkWTSAPI32.dll" fullword ascii
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii
      $s6 = "dYDT.Gtm" fullword ascii
      $s7 = "|PgGeT~^" fullword ascii
      $s8 = "* IiJ)" fullword ascii
      $s9 = "{DllB8qq" fullword ascii
      $s10 = "tfaqbjk" fullword ascii
      $s11 = "nrvgzgl" fullword ascii
      $s12 = "      <!--The ID below indicates application support for Windows 10 -->" fullword ascii
      $s13 = "5n:\\Tk" fullword ascii
      $s14 = "  </compatibility>" fullword ascii
      $s15 = "HHp.JOW" fullword ascii
      $s16 = "      <!--The ID below indicates application support for Windows 8 -->" fullword ascii
      $s17 = "      <!--The ID below indicates application support for Windows 7 -->" fullword ascii
      $s18 = "Wr:\\D;" fullword ascii
      $s19 = "px:\"M$" fullword ascii
      $s20 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 23000KB and
      8 of them
}

rule WinRing0x64_sys {
   meta:
      description = "files - file WinRing0x64.sys.bin"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/"
      date = "2022/07/10"
      hash1 = "11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5"
   strings:
      $s1 = "d:\\hotproject\\winring0\\source\\dll\\sys\\lib\\amd64\\WinRing0.pdb" fullword ascii
      $s2 = "WinRing0.sys" fullword wide
      $s3 = "timestampinfo@globalsign.com0" fullword ascii
      $s4 = "\"GlobalSign Time Stamping Authority1+0)" fullword ascii
      $s5 = "\\DosDevices\\WinRing0_1_2_0" fullword wide
      $s6 = "OpenLibSys.org" fullword wide
      $s7 = ".http://crl.globalsign.net/RootSignPartners.crl0" fullword ascii
      $s8 = "Copyright (C) 2007-2008 OpenLibSys.org. All rights reserved." fullword wide
      $s9 = "1.2.0.5" fullword wide
      $s10 = " Microsoft Code Verification Root0" fullword ascii
      $s11 = "\\Device\\WinRing0_1_2_0" fullword wide
      $s12 = "WinRing0" fullword wide
      $s13 = "hiyohiyo@crystalmark.info0" fullword ascii
      $s14 = "GlobalSign1+0)" fullword ascii
      $s15 = "Noriyuki MIYAZAKI1(0&" fullword ascii
      $s16 = "The modified BSD license" fullword wide
      $s17 = "RootSign Partners CA1" fullword ascii
      $s18 = "\\/.gJ&" fullword ascii
      $s19 = "14012709" ascii
      $s20 = "140127110000Z0q1(0&" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      8 of them
}
