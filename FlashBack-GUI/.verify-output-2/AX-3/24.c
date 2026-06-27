/* =====================================================
 *  Path 24
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - formWifiBasicSet_2G (arg=1, call_ea=0x35eb8, func_ea=0x35bd0, label=certain)
 *        call: strcpy(v39, v18);
 *    - websGetVar (arg=ret, call_ea=0x35df0, func_ea=source, label=source)
 *        call: v18 = websGetVar(wp, v17, "none");
 * ===================================================== */


/* Function: formWifiBasicSet_2G @ 0x35BD0 */
int __fastcall formWifiBasicSet_2G(webs_t wp, char_t *path, char_t *query, char *wl_ifname, char *enable_unity)
{
  size_t v8; // r0
  char_t *Var; // r10
  char_t *v10; // r9
  char_t *v11; // r1
  char_t *v12; // r0
  bool v13; // zf
  char_t *v14; // r5
  int v15; // r11
  size_t v16; // r0
  char_t *v17; // r1
  char_t *v18; // r5
  int mibname; // r0
  const char *v20; // r1
  int v21; // r0
  char *v22; // r1
  size_t v23; // r0
  char_t *v24; // r1
  char_t *v25; // r8
  int v26; // r5
  char_t *v27; // r11
  char_t *v28; // r10
  char_t *v29; // r9
  char_t *v30; // r0
  bool v31; // zf
  char_t *v32; // r4
  bool v33; // zf
  bool v34; // zf
  char_t *v36; // [sp+0h] [bp-110h]
  char_t *v37; // [sp+4h] [bp-10Ch]
  _BYTE *v38; // [sp+Ch] [bp-104h] BYREF
  char v39[256]; // [sp+10h] [bp-100h] BYREF
  WIFI_BUF wifi_buf_enty; // [sp+110h] [bp+0h] BYREF
  _BYTE v41[512]; // [sp+314h] [bp+204h] BYREF
  int v42; // [sp+514h] [bp+404h]
  _BYTE v43[512]; // [sp+518h] [bp+408h] BYREF
  int v44; // [sp+718h] [bp+608h]
  _BYTE v45[512]; // [sp+71Ch] [bp+60Ch] BYREF
  int v46; // [sp+91Ch] [bp+80Ch]

  memset(&wifi_buf_enty, 0, sizeof(wifi_buf_enty));
  wifi_buf_enty.max_length = 256;
  v8 = strlen(query);
  if ( !strncmp(query, "0", v8) )
  {
    Var = websGetVar(wp, "wrlEn", "1");
    v10 = websGetVar(wp, "hideSsid", "0");
    v11 = "ssid";
  }
  else
  {
    Var = websGetVar(wp, "wrlEn_5g", "1");
    v10 = websGetVar(wp, "hideSsid_5g", "0");
    v11 = "ssid_5g";
  }
  v12 = websGetVar(wp, v11, &byte_794DF);
  v13 = v12 == 0;
  if ( v12 )
    v13 = v10 == 0;
  v14 = v12;
  v15 = v13;
  if ( v13 )
    return 1;
  memset(&wifi_buf_enty, v15, wifi_buf_enty.max_length);
  memset(wifi_buf_enty.mib_buf, v15, wifi_buf_enty.max_length);
  set_idx_to_mib(path, "bss_hide", v10, &wifi_buf_enty);
  set_idx_to_mib(path, "bss_enable", Var, &wifi_buf_enty);
  if ( *v14 )
    set_idx_to_mib(path, "bss_ssid", v14, &wifi_buf_enty);
  memset(v39, 0, sizeof(v39));
  v42 = 256;
  v38 = v41;
  memset(v41, 0, sizeof(v41));
  v16 = strlen(query);
  v17 = !strncmp(query, "0", v16) ? "security" : "security_5g";
  v18 = websGetVar(wp, v17, "none");
  if ( !v18 )
    return 1;
  mibname = wifi_get_mibname(path, "bss_security", v38);
  GetValue(mibname, v38 + 256);
  SetValue(v38, v18);
  if ( !strcmp(v18, "wpapsk")
    || !strcmp(v18, "wpa2psk")
    || !strcmp(v18, "wpawpa2psk")
    || !strcmp(v18, "wpa3sae")
    || !strcmp(v18, "wpa3saewpa2psk") )
  {
    v20 = "wpapsk";
  }
  else
  {
    v20 = v18;
  }
  SetValue(v38, v20);
  strcpy(v39, v18);
  v21 = wifi_get_mibname(path, "bss_wpapsk_type", v38);
  GetValue(v21, v38 + 256);
  if ( !strcmp(v18, "wpapsk") )
  {
    v22 = "psk";
  }
  else if ( !strcmp(v18, "wpa2psk") )
  {
    v22 = "psk2";
  }
  else if ( !strcmp(v18, "wpawpa2psk") )
  {
    v22 = "psk+psk2";
  }
  else if ( !strcmp(v18, "wpa3sae") )
  {
    v22 = "wpa3sae";
  }
  else
  {
    if ( strcmp(v18, "wpa3saewpa2psk") )
      goto LABEL_34;
    v22 = "wpa3sae+psk2";
  }
  SetValue(v38, v22);
LABEL_34:
  set_idx_to_mib(path, "bss_wpapsk_crypto", "aes", &v38);
  v44 = 256;
  memset(v43, 0, sizeof(v43));
  v23 = strlen(query);
  if ( !strncmp(query, "0", v23) )
    v24 = "wrlPwd";
  else
    v24 = "wrlPwd_5g";
  v25 = websGetVar(wp, v24, "12345678");
  if ( !v25 )
    return 1;
  v26 = strcmp(v39, "none");
  if ( v26 )
  {
    v26 = strcmp(v39, "wep");
    if ( !v26 )
    {
      v46 = 256;
      memset(v45, 0, sizeof(v45));
      v27 = websGetVar(wp, "wepauth", "open");
      v28 = websGetVar(wp, "wepkey", "1");
      v29 = websGetVar(wp, "wepkey1", "12345");
      v36 = websGetVar(wp, "wepkey2", "12345");
      v37 = websGetVar(wp, "wepkey3", "12345");
      v30 = websGetVar(wp, "wepkey4", "12345");
      v31 = v28 == 0;
      if ( v28 )
        v31 = v27 == 0;
      v32 = v30;
      if ( !v31 )
      {
        v33 = v36 == 0;
        if ( v36 )
          v33 = v29 == 0;
        if ( !v33 )
        {
          v34 = v30 == 0;
          if ( v30 )
            v34 = v37 == 0;
          if ( !v34 )
          {
            set_idx_to_mib(path, "bss_wep_type", v27, v45);
            set_idx_to_mib(path, "bss_wep_key", v28, v45);
            set_idx_to_mib(path, "bss_wep_key1", v29, v45);
            set_idx_to_mib(path, "bss_wep_key2", v36, v45);
            set_idx_to_mib(path, "bss_wep_key3", v37, v45);
            set_idx_to_mib(path, "bss_wep_key4", v32, v45);
            return v26;
          }
        }
      }
      return 1;
    }
    if ( !strcmp(v39, "wpapsk")
      || !strcmp(v39, "wpa2psk")
      || !strcmp(v39, "wpawpa2psk")
      || !strcmp(v39, "wpa3sae")
      || !strcmp(v39, "wpa3saewpa2psk") )
    {
      set_idx_to_mib(path, "bss_wpapsk_key", v25, v43);
    }
    return 0;
  }
  return v26;
}
