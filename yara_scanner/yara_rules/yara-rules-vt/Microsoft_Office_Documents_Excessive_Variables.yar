rule Microsoft_Office_Documents_Excessive_Variables
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects Microsoft Office documents containing Visual Basic scripts that contain large numbers of terse variables or instances of obfuscated value construction. Such content is indicative of attempts to evade malware detection."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Labs Empirical Observations"
        labs_reference = "https://labs.inquest.net/dfi/sha256/ecf58457f32a720f2e3036342115c8833dd50b93d1fccf901a3054a72559fa44"
        labs_pivot     = "https://labs.inquest.net/dfi/search/alert/Suspicious%20Document%20Variables"
        samples        = "ecf58457f32a720f2e3036342115c8833dd50b93d1fccf901a3054a72559fa44"

	strings:
			$office = /^\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00/

$vb1 = "VBE" nocase wide ascii
$vb2 = "VBA" nocase wide ascii

$ole1 = "OLE" nocase wide ascii
$ole2 = "stdole" nocase wide ascii
                

$v1 = { 80 00 00 ff 03 03 0? }
$v2 = { 84 08 00 ff 03 03 0? } 
$v3 = { b600 0200 [2-8] b600 0200 [2-8] b600 0200 [2-8] b600 0200 [2-8] b600 0200 }
	condition:
			filesize < 700KB 
and $office 
and any of ($vb*) 
and any of ($ole*) 
and (#v1 > 32 or #v2 > 32 or #v3 > 32)
}