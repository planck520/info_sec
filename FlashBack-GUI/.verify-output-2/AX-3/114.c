/* =====================================================
 *  Path 114
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - fromGetWirelessRepeat_wifi_chkHz (arg=1, call_ea=0x39628, func_ea=0x395ac, label=certain)
 *        call: GetValue("wl.extra_hand", wl_hand);
 *    - wlSetExternParameter (arg=1, call_ea=0x39fdc, func_ea=0x39cd4, label=needs_check)
 *        call: SetValue("wl.extra_hand", v25);
 *    - websGetVar (arg=ret, call_ea=0x39d64, func_ea=source, label=source)
 *        call: v25 = websGetVar(wp, "handset", "0");
 * ===================================================== */


/* Function: fromGetWirelessRepeat_wifi_chkHz @ 0x395AC */
void __fastcall fromGetWirelessRepeat_wifi_chkHz(cJSON_0 *root, char *radio_ifname, char *extern_ifname)
{
  cJSON *String; // r0
  int mibname; // r0
  int v8; // r0
  const char *v9; // r1
  cJSON *v10; // r0
  char *v11; // r1
  cJSON *v12; // r0
  char wl_hand[8]; // [sp+14h] [bp-374h] BYREF
  char wifi_mode[16]; // [sp+1Ch] [bp-36Ch] BYREF
  char wpapsk_type[16]; // [sp+2Ch] [bp-35Ch] BYREF
  char wpapsk_crypto[16]; // [sp+3Ch] [bp-34Ch] BYREF
  char tmp_value[16]; // [sp+4Ch] [bp-33Ch] BYREF
  char mib_name[256]; // [sp+5Ch] [bp-32Ch] BYREF
  WIFI_BUF wifi_buf_enty; // [sp+15Ch] [bp-22Ch] BYREF

  memset(wifi_mode, 0, sizeof(wifi_mode));
  memset(wl_hand, 0, sizeof(wl_hand));
  memset(mib_name, 0, sizeof(mib_name));
  memset(&wifi_buf_enty, 0, sizeof(wifi_buf_enty));
  wifi_buf_enty.max_length = 256;
  GetValue("wl.extra_hand", wl_hand);
  get_index_mib_2cJSONString(root, "country_code", radio_ifname, "countrycode", &wifi_buf_enty);
  get_index_mib_2cJSONString(root, "wl_mode", radio_ifname, "workmode", &wifi_buf_enty);
  strncpy(wifi_mode, wifi_buf_enty.wifi_buf, 0x10u);
  if ( strcmp(wifi_mode, "ap") )
  {
    String = cJSON_CreateString(wl_hand);
    cJSON_AddItemToObject((cJSON *)root, "handset", String);
    get_index_mib_2cJSONString(root, "ssid", extern_ifname, "extend_ssid", &wifi_buf_enty);
    get_index_mib_2cJSONString(root, "mac", extern_ifname, "extend_mac", &wifi_buf_enty);
    get_index_mib_2cJSONString(root, "security", extern_ifname, "extend_security", &wifi_buf_enty);
    if ( !strncasecmp(wifi_buf_enty.wifi_buf, "wpapsk", 6u) )
    {
      memset(wpapsk_type, 0, sizeof(wpapsk_type));
      memset(wpapsk_crypto, 0, sizeof(wpapsk_crypto));
      memset(tmp_value, 0, sizeof(tmp_value));
      mibname = wifi_get_mibname(extern_ifname, "extend_wpapsk_type", mib_name);
      GetValue(mibname, wpapsk_type);
      v8 = wifi_get_mibname(extern_ifname, "extend_wpapsk_crypto", mib_name);
      GetValue(v8, wpapsk_crypto);
      if ( !strcmp(wpapsk_type, "psk") )
      {
        v9 = "wpa";
      }
      else if ( !strcmp(wpapsk_type, "psk2") )
      {
        v9 = "wpa2";
      }
      else if ( !strcmp(wpapsk_type, "wpa3sae+psk2") )
      {
        v9 = "wpa2&wpa3";
      }
      else
      {
        v9 = "wpa&wpa2";
      }
      strcpy(tmp_value, v9);
      v10 = cJSON_CreateString(tmp_value);
      cJSON_AddItemToObject((cJSON *)root, "wpapsk_type", v10);
      if ( !strcmp(wpapsk_crypto, "tkip+aes") )
        v11 = "tkip&aes";
      else
        v11 = wpapsk_crypto;
      strcpy(tmp_value, v11);
      v12 = cJSON_CreateString(tmp_value);
      cJSON_AddItemToObject((cJSON *)root, "wpapsk_crypto", v12);
      get_index_mib_2cJSONString(root, "wpapsk_key", extern_ifname, "extend_wpapsk_key", &wifi_buf_enty);
      get_index_mib_2cJSONString(root, "uptime", extern_ifname, "extern_wpapsk_rekey_time", &wifi_buf_enty);
    }
  }
}


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
