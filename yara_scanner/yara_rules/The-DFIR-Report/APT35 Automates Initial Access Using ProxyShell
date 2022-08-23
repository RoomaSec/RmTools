rule files_dhvqx {
   meta:
      description = "9893_files - file dhvqx.aspx"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
      date = "2022-03-21"
      hash1 = "c5aae30675cc1fd83fd25330cec245af744b878a8f86626d98b8e7fcd3e970f8"
   strings:
      $s1 = "eval(Request['exec_code'],'unsafe');Response.End;" fullword ascii
      $s2 = "6<script language='JScript' runat='server'>" fullword ascii
      $s3 = "AEALAAAAAAAAAAA" fullword ascii
      $s4 = "AFAVAJA" fullword ascii
      $s5 = "AAAAAAV" fullword ascii
      $s6 = "LAAAAAAA" fullword ascii
      $s7 = "ANAZAQA" fullword ascii
      $s8 = "ALAAAAA" fullword ascii
      $s9 = "AAAAAEA" ascii
      $s10 = "ALAHAUA" fullword ascii
   condition:
      uint16(0) == 0x4221 and filesize < 800KB and
      ($s1 and $s2)  and 4 of them
}


rule aspx_dyukbdcxjfi {
   meta:
      description = "9893_files - file aspx_dyukbdcxjfi.aspx"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
      date = "2022-03-21"
      hash1 = "84f77fc4281ebf94ab4897a48aa5dd7092cc0b7c78235965637eeef0908fb6c7"
   strings:
      $s1 = "string[] commands = exec_code.Substring(\"run \".Length).Split(new[] { ';' }, StringSplitOptions.RemoveEmpty" ascii
      $s2 = "string[] commands = exec_code.Substring(\"run \".Length).Split(new[] { ';' }, StringSplitOptions.RemoveEmpty" ascii
      $s3 = "var dstFile = Path.Combine(dstDir, Path.GetFileName(httpPostedFile.FileName));" fullword ascii
      $s4 = "info.UseShellExecute = false;" fullword ascii
      $s5 = "using (StreamReader streamReader = process.StandardError)" fullword ascii
      $s6 = "return httpPostedFile.FileName + \" Uploaded to: \" + dstFile;" fullword ascii
      $s7 = "else if (exec_code.StartsWith(\"download \"))" fullword ascii
      $s8 = "string[] parts = exec_code.Substring(\"download \".Length).Split(' ');" fullword ascii
      $s9 = "Response.AppendHeader(\"Content-Disposition\", \"attachment; filename=\" + fileName);" fullword ascii
      $s10 = "result = result + Environment.NewLine + \"ERROR:\" + Environment.NewLine + error;" fullword ascii
      $s11 = "else if (exec_code == \"get\")" fullword ascii
      $s12 = "int fileLength = httpPostedFile.ContentLength;" fullword ascii
   condition:
      uint16(0) == 0x4221 and filesize < 800KB and
      8 of them
}


rule files_user {
   meta:
      description = "9893_files - file user.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
      date = "2022-03-21"
      hash1 = "7b5fbbd90eab5bee6f3c25aa3c2762104e219f96501ad6a4463e25e6001eb00b"
   strings:
      $x1 = "PA<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVer" ascii
      $s2 = "\", or \"requireAdministrator\" --> <v3:requestedExecutionLevel level=\"requireAdministrator\" /> </v3:requestedPrivileges> </v3" ascii
      $s3 = "-InitOnceExecuteOnce" fullword ascii
      $s4 = "0\"> <dependency> <dependentAssembly> <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0." ascii
      $s5 = "s:v3=\"urn:schemas-microsoft-com:asm.v3\"> <v3:security> <v3:requestedPrivileges> <!-- level can be \"asInvoker\", \"highestAvai" ascii
      $s6 = "PB_GadgetStack_%I64i" fullword ascii
      $s7 = "PB_DropAccept" fullword ascii
      $s8 = "rocessorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /> </dependentAssembly> </dependency> <v3:trustInf" ascii
      $s9 = "PB_PostEventMessage" fullword ascii
      $s10 = "PB_WindowID" fullword ascii
      $s11 = "?GetLongPathNameA" fullword ascii
      $s12 = "Memory page error" fullword ascii
      $s13 = "PPPPPPH" fullword ascii
      $s14 = "YZAXAYH" fullword ascii
      $s15 = "%d:%I64d:%I64d:%I64d" fullword ascii
      $s16 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii
      $s17 = "PYZAXAYH" fullword ascii
      $s18 = "PB_MDI_Gadget" fullword ascii
      $s19 = "PA<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVer" ascii
      $s20 = " 46B722FD25E69870FA7711924BC5304D 787242D55F2C49A23F5D97710D972108 A2DB26CE3BBE7B2CB12F9BEFB37891A3" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}


rule task_update {
   meta:
      description = "9893_files - file task_update.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
      date = "2022-03-21"
      hash1 = "12c6da07da24edba13650cd324b2ad04d0a0526bb4e853dee03c094075ff6d1a"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii
      $s2 = " or \"requireAdministrator\" --> <v3:requestedExecutionLevel level=\"requireAdministrator\" /> </v3:requestedPrivileges> </v3:se" ascii
      $s3 = "-InitOnceExecuteOnce" fullword ascii
      $s4 = "> <dependency> <dependentAssembly> <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0" ascii
      $s5 = "v3=\"urn:schemas-microsoft-com:asm.v3\"> <v3:security> <v3:requestedPrivileges> <!-- level can be \"asInvoker\", \"highestAvaila" ascii
      $s6 = "PB_GadgetStack_%I64i" fullword ascii
      $s7 = "PB_DropAccept" fullword ascii
      $s8 = "PB_PostEventMessage" fullword ascii
      $s9 = "PB_WindowID" fullword ascii
      $s10 = "?GetLongPathNameA" fullword ascii
      $s11 = "cessorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /> </dependentAssembly> </dependency> <v3:trustInfo " ascii
      $s12 = "Memory page error" fullword ascii
      $s13 = "PPPPPPH" fullword ascii
      $s14 = "YZAXAYH" fullword ascii
      $s15 = "%d:%I64d:%I64d:%I64d" fullword ascii
      $s16 = "PYZAXAYH" fullword ascii
      $s17 = "PB_MDI_Gadget" fullword ascii
      $s18 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii
      $s19 = " 11FCC18FB2B55FC3C988F6A76FCF8A2D 56D49E57AD1A051BF62C458CD6F3DEA9 6104990DFEA3DFAB044FAF960458DB09" fullword wide
      $s20 = "PostEventClass" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}


rule App_Web_vjloy3pa {
   meta:
      description = "9893_files - file App_Web_vjloy3pa.dll"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
      date = "2022-03-21"
      hash1 = "faa315db522d8ce597ac0aa957bf5bde31d91de94e68d5aefac4e3e2c11aa970"
   strings:
      $x2 = "hSystem.ComponentModel.DataAnnotations, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
      $s3 = "MSystem.Xml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s4 = "RSystem.Xml.Linq, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s5 = "ZSystem.ServiceModel.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
      $s6 = "YSystem.Web.DynamicData, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
      $s7 = "XSystem.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
      $s8 = "VSystem.Web.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
      $s9 = "MSystem.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
      $s10 = "WSystem.Configuration, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
      $s11 = "`System.Data.DataSetExtensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s12 = "NSystem.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s13 = "ZSystem.WorkflowServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
      $s14 = "WSystem.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s15 = "aSystem.ServiceModel.Activation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
      $s16 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" wide /* base64 encoded string '' */
      $s17 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" wide /* base64 encoded string '' */
      $s18 = "aSystem.Web.ApplicationServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
      $s19 = "\\System.EnterpriseServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
      $s20 = "SMicrosoft.CSharp, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}


rule _user_task_update_0 {
   meta:
      description = "9893_files - from files user.exe, task_update.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
      date = "2022-03-21"
      hash1 = "7b5fbbd90eab5bee6f3c25aa3c2762104e219f96501ad6a4463e25e6001eb00b"
      hash2 = "12c6da07da24edba13650cd324b2ad04d0a0526bb4e853dee03c094075ff6d1a"
   strings:
      $s1 = "-InitOnceExecuteOnce" fullword ascii
      $s2 = "PB_GadgetStack_%I64i" fullword ascii
      $s3 = "PB_DropAccept" fullword ascii
      $s4 = "PB_PostEventMessage" fullword ascii
      $s5 = "PB_WindowID" fullword ascii
      $s6 = "?GetLongPathNameA" fullword ascii
      $s7 = "Memory page error" fullword ascii
      $s8 = "PPPPPPH" fullword ascii
      $s9 = "YZAXAYH" fullword ascii
      $s10 = "%d:%I64d:%I64d:%I64d" fullword ascii
      $s11 = "PYZAXAYH" fullword ascii
      $s12 = "PB_MDI_Gadget" fullword ascii
      $s13 = "PostEventClass" fullword ascii
      $s14 = "t$hYZAXAYH" fullword ascii
      $s15 = "$YZAXAYH" fullword ascii
      $s16 = "Floating-point underflow (exponent too small)" fullword ascii
      $s17 = "Inexact floating-point result" fullword ascii
      $s18 = "Single step trap" fullword ascii
      $s19 = "Division by zero (floating-point)" fullword ascii
      $s20 = "tmHcI(H" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}
