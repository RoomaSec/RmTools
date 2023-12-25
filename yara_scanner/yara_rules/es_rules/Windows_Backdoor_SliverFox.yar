rule Detect_SliverFox_String {
    meta:
        description = "Detect files is `SliverFox` malware"
        author = "huoji"
        date = "2023-12-25"

    strings:
        $getserver_string = "GETSERVER"
        $signature_autorun_QuickLaunch = {84 DB 79 ?? 8B C3 83 ?? ?? 03 ?? ?? ?? ?? ?? 83 ?? ?? 50 57 53 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 ?? ?? 0F ?? ?? ?? ?? ?? FF ?? ?? 57 E8 ?? ?? ?? ?? E9 ?? ?? ?? ??}
        $signature_sleep = {55 8B EC 83 ?? ?? FF ?? ?? ?? ?? ?? 89 45 ?? 68 ?? ?? ?? ?? FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 89 45 ?? 8B 45 ?? 2B 45 ?? 3D ?? ?? ?? ?? 7C ?? 32 C0 EB ??}
        $signature_junk_call = {E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C ?? ?? ?? ?? ??}
        $signature_decrypt_memory = {2B FA 85 C0 74 ?? 0F B7 34 17 66 85 F6 74 ?? 66 89 32 83 ?? ?? 48 83 ?? ?? 75 ?? 85 C9 75 ?? 83 ?? ?? 33 C0 F7 D9 66 89 02 1B C9}
        $signature_command_switch = {41 8B EC 48 8B D9 0F ?? ?? ?? ?? ?? 0F ?? ?? ?? ?? ?? 8D 42 ?? 3D ?? ?? ?? ?? 0F ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 98 0F B6 ?? ?? ?? ?? ?? ?? 8B 8C ?? ?? ?? ?? ?? 48 03 CF FF E1 41 8B 08 83 ?? ?? 7D ?? B8 ?? ?? ?? ?? 48 8B ?? ?? ?? 48 ?? ?? ?? 41 5D 41 5C 5F 5E 5D C3 B8 ?? ?? ?? ?? 3B C8 0F 4F C8 89 8B ?? ?? ?? ?? E9 ?? ?? ?? ?? 49 63 00 85 C0 78 ?? 48 89 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 41 39 28 41 0F 95 C4 44 89 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 41 39 28 41 0F 95 C4 44 89 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 41 39 28 41 0F 95 C4 44 89 ?? ?? ?? ?? ?? E9 ?? ?? ?? ??}
        $signature_encrypt_memory = {48 89 ?? ?? ?? 48 89 ?? ?? ?? 4C 89 ?? ?? ?? 4C 89 ?? ?? ?? 48 ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B F8 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? 48 8B ?? ?? ?? 48 8B ?? ?? ?? 4C 8B ?? ?? ?? 4C 8B ?? ?? ?? 4C 8B D1 41 FF E7}
        $signature_youdao = { 33 FF 89 7C ?? ?? 0F 57 C0 0F 11 ?? ?? 66 ?? ?? ?? ?? ?? ?? ?? F3 0F ?? ?? ?? 40 88 ?? ?? 44 8D ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8D ?? ?? E8 ?? ?? ?? ?? 48 8D ?? ?? 48 89 ?? ?? ?? 48 8B D3 48 8D ?? ?? E8 ?? ?? ?? ?? 48 8B D8 49 8B D4 48 8D ?? ?? ?? E8 ?? ?? ?? ?? 90 4C 8B CB 4C 8B C0 48 8D ?? ?? ?? E8 ?? ?? ?? ?? }
        $signature_connect_host = {A1 ?? ?? ?? ?? 83 ?? ?? 56 57 8B F9 50 68 ?? ?? ?? ?? 8D 4C ?? ?? 68 ?? ?? ?? ?? 51 FF ?? ?? ?? ?? ?? 83 ?? ?? 8D 54 ?? ?? 52 6A ?? 6A ?? FF ?? ?? ?? ?? ??}
        $signature_anti_vm = { 83 65 ?? ?? 8D 85 ?? ?? ?? ?? 89 46 ?? E8 ?? ?? ?? ?? 85 C0 5E 0F ?? ?? ?? ?? ?? 20 45 ?? 8D 45 ?? 50 C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? }
    condition:
        any of them
}