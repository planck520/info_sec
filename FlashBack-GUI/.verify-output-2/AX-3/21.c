/* =====================================================
 *  Path 21
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - formWifiBasicSet_5G (arg=1, call_ea=0x365f8, func_ea=0x363c0, label=certain)
 *        call: strcpy(s, v12);
 *    - websGetVar (arg=ret, call_ea=0x3653c, func_ea=source, label=source)
 *        call: v12 = websGetVar(wp, "security_5g", "none");
 * ===================================================== */


/* Function: formWifiBasicSet_5G @ 0x363C0 */
int __fastcall formWifiBasicSet_5G(webs_t wp, char_t *path, char_t *query, char *wl_ifname)
{
  char_t *Var; // r10
  char_t *v7; // r8
  char_t *v8; // r0
  bool v9; // zf
  int v10; // r9
  char_t *v11; // r7
  char_t *v12; // r4
  int mibname; // r0
  const char *v14; // r1
  int v15; // r0
  char *v16; // r1
  char_t *v17; // r10
  int v18; // r4
  char_t *v19; // r11
  char_t *v20; // r9
  char_t *v21; // r10
  char_t *v22; // r0
  bool v23; // zf
  bool v24; // zf
  bool v25; // zf
  char_t *v27; // [sp+0h] [bp-948h]
  char_t *v28; // [sp+4h] [bp-944h]
  _BYTE *v29; // [sp+Ch] [bp-93Ch] BYREF
  char s[256]; // [sp+10h] [bp-938h] BYREF
  WIFI_BUF wifi_buf_enty; // [sp+110h] [bp-838h] BYREF
  _BYTE v32[512]; // [sp+314h] [bp-634h] BYREF
  int v33; // [sp+514h] [bp-434h]
  _BYTE v34[512]; // [sp+518h] [bp-430h] BYREF
  int v35; // [sp+718h] [bp-230h]
  _BYTE v36[512]; // [sp+71Ch] [bp-22Ch] BYREF
  int v37; // [sp+91Ch] [bp-2Ch]

  memset(&wifi_buf_enty, 0, sizeof(wifi_buf_enty));
  wifi_buf_enty.max_length = 256;
  Var = websGetVar(wp, "wrlEn_5g", "1");
  v7 = websGetVar(wp, "hideSsid_5g", "0");
  v8 = websGetVar(wp, "ssid_5g", &byte_794DF);
  v9 = v8 == 0;
  if ( v8 )
    v9 = v7 == 0;
  v10 = v9;
  if ( v9 )
    return 1;
  v11 = v8;
  memset(&wifi_buf_enty, v10, wifi_buf_enty.max_length);
  memset(wifi_buf_enty.mib_buf, v10, wifi_buf_enty.max_length);
  set_idx_to_mib(path, "bss_hide", v7, &wifi_buf_enty);
  set_idx_to_mib(path, "bss_enable", Var, &wifi_buf_enty);
  if ( *v11 )
    set_idx_to_mib(path, "bss_ssid", v11, &wifi_buf_enty);
  memset(s, 0, sizeof(s));
  v33 = 256;
  v29 = v32;
  memset(v32, 0, sizeof(v32));
  v12 = websGetVar(wp, "security_5g", "none");
  if ( !v12 )
    return 1;
  mibname = wifi_get_mibname(path, "bss_security", v29);
  GetValue(mibname, v29 + 256);
  if ( !strcmp(v12, "wpapsk")
    || !strcmp(v12, "wpa2psk")
    || !strcmp(v12, "wpawpa2psk")
    || !strcmp(v12, "wpa3sae")
    || !strcmp(v12, "wpa3saewpa2psk") )
  {
    v14 = "wpapsk";
  }
  else
  {
    v14 = v12;
  }
  SetValue(v29, v14);
  strcpy(s, v12);
  v15 = wifi_get_mibname(path, "bss_wpapsk_type", v29);
  GetValue(v15, v29 + 256);
  if ( !strcmp(v12, "wpapsk") )
  {
    v16 = "psk";
  }
  else if ( !strcmp(v12, "wpa2psk") )
  {
    v16 = "psk2";
  }
  else if ( !strcmp(v12, "wpawpa2psk") )
  {
    v16 = "psk+psk2";
  }
  else if ( !strcmp(v12, "wpa3sae") )
  {
    v16 = "wpa3sae";
  }
  else
  {
    if ( strcmp(v12, "wpa3saewpa2psk") )
      goto LABEL_28;
    v16 = "wpa3sae+psk2";
  }
  SetValue(v29, v16);
LABEL_28:
  set_idx_to_mib(path, "bss_wpapsk_crypto", "aes", &v29);
  v35 = 256;
  memset(v34, 0, sizeof(v34));
  v17 = websGetVar(wp, "wrlPwd_5g", "12345678");
  if ( !v17 )
    return 1;
  v18 = strcmp(s, "none");
  if ( v18 )
  {
    v18 = strcmp(s, "wep");
    if ( !v18 )
    {
      v37 = 256;
      memset(v36, 0, sizeof(v36));
      v19 = websGetVar(wp, "wepauth_5g", "open");
      v20 = websGetVar(wp, "wepkey_5g", "1");
      v21 = websGetVar(wp, "wepkey1_5g", "12345");
      v27 = websGetVar(wp, "wepkey2_5g", "12345");
      v28 = websGetVar(wp, "wepkey3_5g", "12345");
      v22 = websGetVar(wp, "wepkey4_5g", "12345");
      v23 = v20 == 0;
      if ( v20 )
        v23 = v19 == 0;
      if ( !v23 )
      {
        v24 = v27 == 0;
        if ( v27 )
          v24 = v21 == 0;
        if ( !v24 )
        {
          v25 = v22 == 0;
          if ( v22 )
            v25 = v28 == 0;
          if ( !v25 )
          {
            set_idx_to_mib(path, "bss_wep_type", v19, v36);
            set_idx_to_mib(path, "bss_wep_key", v20, v36);
            set_idx_to_mib(path, "bss_wep_key1", v21, v36);
            set_idx_to_mib(path, "bss_wep_key2", v27, v36);
            set_idx_to_mib(path, "bss_wep_key3", v28, v36);
            set_idx_to_mib(path, "bss_wep_key4", v20, v36);
            return v18;
          }
        }
      }
      return 1;
    }
    if ( !strcmp(s, "wpapsk")
      || !strcmp(s, "wpa2psk")
      || !strcmp(s, "wpawpa2psk")
      || !strcmp(s, "wpa3sae")
      || !strcmp(s, "wpa3saewpa2psk") )
    {
      set_idx_to_mib(path, "bss_wpapsk_key", v17, v34);
    }
    return 0;
  }
  return v18;
}
