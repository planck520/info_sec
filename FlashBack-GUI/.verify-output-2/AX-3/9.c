/* =====================================================
 *  Path 9
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - wlSetExternParameter (arg=1, call_ea=0x39f3c, func_ea=0x39cd4, label=needs_check)
 *        call: strcpy(wpapsk_cryptovalue, v18);
 *    - websGetVar (arg=ret, call_ea=0x39e78, func_ea=source, label=source)
 *        call: v15 = websGetVar(wp, "wpapsk_crypto", "aes");
 * ===================================================== */


/* Function: wlSetExternParameter @ 0x39CD4 */
int __fastcall wlSetExternParameter(webs_t wp, char *wifi_chkHz, char *wl_extern)
{
  char *v6; // r7
  char_t *Var; // r9
  char_t *v8; // r11
  int mibname; // r0
  char_t *v10; // r9
  int v11; // r0
  int v12; // r0
  int v13; // r0
  char_t *v14; // r9
  char_t *v15; // r10
  char_t *v16; // r0
  const char *v17; // r1
  const char *v18; // r1
  int v19; // r0
  int v20; // r0
  int v21; // r0
  int v22; // r0
  int v23; // r0
  char_t *v25; // [sp+8h] [bp-6Ch]
  char mib_name[16]; // [sp+Ch] [bp-68h] BYREF
  char os_ifname[16]; // [sp+1Ch] [bp-58h] BYREF
  char wpapsk_typevalue[16]; // [sp+2Ch] [bp-48h] BYREF
  char wpapsk_cryptovalue[16]; // [sp+3Ch] [bp-38h] BYREF

  memset(mib_name, 0, sizeof(mib_name));
  memset(os_ifname, 0, sizeof(os_ifname));
  v6 = &byte_794DF;
  Var = websGetVar(wp, "ssid", &byte_794DF);
  v8 = websGetVar(wp, "mac", &byte_794DF);
  v25 = websGetVar(wp, "handset", "0");
  set_cn_ssid_ori_encode(wifi_chkHz, Var);
  mibname = wifi_get_mibname(wl_extern, "extend_ssid", mib_name);
  SetValue(mibname, Var);
  v10 = websGetVar(wp, "security", "wpapsk");
  v11 = wifi_get_mibname(wl_extern, "extend_security", mib_name);
  SetValue(v11, v10);
  if ( !strcmp(v10, "none") )
  {
    v12 = wifi_get_mibname(wl_extern, "extend_wpapsk_type", mib_name);
    SetValue(v12, &byte_794DF);
    v13 = wifi_get_mibname(wl_extern, "extend_wpapsk_crypto", mib_name);
    SetValue(v13, &byte_794DF);
LABEL_17:
    v21 = wifi_get_mibname(wl_extern, "extend_wpapsk_key", mib_name);
    SetValue(v21, v6);
    v22 = wifi_get_mibname(wl_extern, "extend_mac", mib_name);
    SetValue(v22, v8);
    v23 = wifi_get_mibname(wl_extern, "extend_enable", mib_name);
    SetValue(v23, "1");
    SetValue("wl.extra_hand", v25);
    tpi_wifi_get_osifname(wl_extern, os_ifname);
    SetValue("wl.wisp.ifname", os_ifname);
    return 0;
  }
  if ( !strcmp(v10, "wpapsk") )
  {
    v14 = websGetVar(wp, "wpapsk_type", "wpa&wpa2");
    v15 = websGetVar(wp, "wpapsk_crypto", "aes");
    v16 = websGetVar(wp, "wpapsk_key", &byte_794DF);
    v6 = v16;
    if ( *v16 || strlen(v16) > 7 )
    {
      if ( !strcmp(v14, "wpa") )
      {
        v17 = "psk";
      }
      else if ( !strcmp(v14, "wpa2") )
      {
        v17 = "psk2";
      }
      else if ( !strcmp(v14, "wpa2&wpa3") )
      {
        v17 = "wpa3sae+psk2";
      }
      else
      {
        v17 = "psk+psk2";
      }
      strcpy(wpapsk_typevalue, v17);
      if ( !strcmp(v15, "tkip&aes") )
        v18 = "tkip+aes";
      else
        v18 = v15;
      strcpy(wpapsk_cryptovalue, v18);
      v19 = wifi_get_mibname(wl_extern, "extend_wpapsk_type", mib_name);
      SetValue(v19, wpapsk_typevalue);
      v20 = wifi_get_mibname(wl_extern, "extend_wpapsk_crypto", mib_name);
      SetValue(v20, wpapsk_cryptovalue);
      goto LABEL_17;
    }
  }
  return -1;
}
