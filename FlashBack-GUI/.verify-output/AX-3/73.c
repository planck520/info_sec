/* =====================================================
 *  Path 73
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formWifiRadioGet_2G (arg=1, call_ea=0x34d98, func_ea=0x34ab0, label=certain)
 *        call: GetValue("2.4_nettype", web_nettype);
 *    - formWifiRadioSet_2G (arg=1, call_ea=0x353a8, func_ea=0x35220, label=needs_check)
 *        call: SetValue("2.4_nettype", v9);
 *    - websGetVar (arg=ret, call_ea=0x35300, func_ea=source, label=source)
 *        call: v9 = websGetVar(wp, "adv_mode", "bgn");
 * ===================================================== */


/* Function: formWifiRadioGet_2G @ 0x34AB0 */
void __fastcall formWifiRadioGet_2G(cJSON_0 *root, char *wl_ifname)
{
  int mibname; // r0
  cJSON *String; // r0
  cJSON *v6; // r0
  cJSON *Array; // r4
  int v8; // r0
  cJSON *v9; // r0
  cJSON *v10; // r0
  channel_list_inparam_t wifi_24g_inparam; // [sp+24h] [bp-1Ch] BYREF
  char ifname[16]; // [sp+30h] [bp-10h] BYREF
  char os_ifname[16]; // [sp+40h] [bp+0h] BYREF
  char web_nettype[16]; // [sp+50h] [bp+10h] BYREF
  chan_info_t chan_info; // [sp+60h] [bp+20h] BYREF
  channel_list_t channel_list; // [sp+78h] [bp+38h] BYREF
  char wifi_band_value[256]; // [sp+FCh] [bp+BCh] BYREF
  char wifi_countrycode[256]; // [sp+1FCh] [bp+1BCh] BYREF
  char mib_name[256]; // [sp+2FCh] [bp+2BCh] BYREF
  WIFI_BUF wifi_buf_enty; // [sp+3FCh] [bp+3BCh] BYREF

  memset(ifname, 0, sizeof(ifname));
  memset(os_ifname, 0, sizeof(os_ifname));
  memset(wifi_band_value, 0, sizeof(wifi_band_value));
  memset(wifi_countrycode, 0, sizeof(wifi_countrycode));
  memset(mib_name, 0, sizeof(mib_name));
  memset(web_nettype, 0, sizeof(web_nettype));
  memset(&wifi_buf_enty, 0, sizeof(wifi_buf_enty));
  wifi_buf_enty.max_length = 256;
  *(_DWORD *)wifi_24g_inparam.country = 0;
  memset(wifi_buf_enty.mib_buf, 0, sizeof(wifi_buf_enty.mib_buf));
  get_index_mib_2cJSONString(root, "adv_country", wl_ifname, "countrycode", &wifi_buf_enty);
  mibname = wifi_get_mibname(wl_ifname, "countrycode", mib_name);
  GetValue(mibname, wifi_countrycode);
  strcpy(wifi_24g_inparam.country, wifi_countrycode);
  memset(&chan_info, 0, sizeof(chan_info));
  sprintf(ifname, "%s.0", wl_ifname);
  tpi_wifi_get_osifname(ifname, os_ifname);
  tpi_wifi_get_chaninfo(os_ifname, &chan_info);
  String = cJSON_CreateString(chan_info.bandwidth);
  cJSON_AddItemToObject((cJSON *)root, "adv_current_band", String);
  v6 = cJSON_CreateString(chan_info.channel);
  cJSON_AddItemToObject((cJSON *)root, "adv_current_channel", v6);
  memset(&channel_list, 0, sizeof(channel_list));
  sprintf(ifname, "%s.0", wl_ifname);
  tpi_wifi_get_osifname(ifname, os_ifname);
  tpi_wifi_get_channel_list_by_country(os_ifname, 20, 0, *(_DWORD *)wifi_24g_inparam.country, &channel_list);
  if ( channel_list.num > 0 )
  {
    Array = cJSON_CreateArray();
    cJSON_AddItemToObject((cJSON *)root, "channel", Array);
    assembleChannelList2JsonArray((cJSON_0 *)Array, channel_list.channel, channel_list.num);
  }
  v8 = wifi_get_mibname(wl_ifname, "bandwidth", mib_name);
  GetValue(v8, wifi_band_value);
  if ( !strcmp(wifi_band_value, "0") )
    strcpy(wifi_band_value, "auto");
  v9 = cJSON_CreateString(wifi_band_value);
  cJSON_AddItemToObject((cJSON *)root, "adv_band", v9);
  get_index_mib_2cJSONString(root, "adv_channel", wl_ifname, "channel", &wifi_buf_enty);
  get_index_mib_2cJSONString(root, "adv_extend_channel", wl_ifname, "sideband_flag", &wifi_buf_enty);
  GetValue("2.4_nettype", web_nettype);
  v10 = cJSON_CreateString(web_nettype);
  cJSON_AddItemToObject((cJSON *)root, "adv_mode", v10);
}


/* Function: formWifiRadioSet_2G @ 0x35220 */
int __fastcall formWifiRadioSet_2G(webs_t wp, WIFI_BUF *wl_buf, char *wl_ifname, int *wl2g_restart)
{
  char *Var; // r6
  char_t *v8; // r9
  char_t *v9; // r5
  int mibname; // r0
  int v11; // r0
  char *v12; // r1
  bool v13; // zf
  int result; // r0
  int v15; // r0
  int v16; // r0
  int v17; // r0
  int v18; // r0
  int v19; // r0
  const char *v20; // r1
  int v21; // r0
  int v22; // r0
  int v23; // r0
  int v24; // r0
  int v25; // r0
  char web_ofdma_en[8]; // [sp+10h] [bp-2D0h] BYREF
  char mib_channel_24[32]; // [sp+18h] [bp-2C8h] BYREF
  char mib_band_24[32]; // [sp+38h] [bp-2A8h] BYREF
  char mib_mode[32]; // [sp+58h] [bp-288h] BYREF
  char s[32]; // [sp+78h] [bp-268h] BYREF
  _BYTE v32[32]; // [sp+98h] [bp-248h] BYREF
  char mib_name[256]; // [sp+B8h] [bp-228h] BYREF
  _BYTE v34[296]; // [sp+1B8h] [bp-128h] BYREF

  memset(mib_channel_24, 0, sizeof(mib_channel_24));
  memset(mib_band_24, 0, sizeof(mib_band_24));
  memset(mib_mode, 0, sizeof(mib_mode));
  memset(mib_name, 0, sizeof(mib_name));
  memset(web_ofdma_en, 0, sizeof(web_ofdma_en));
  Var = websGetVar(wp, "adv_band", "40");
  v8 = websGetVar(wp, "adv_channel", "0");
  v9 = websGetVar(wp, "adv_mode", "bgn");
  mibname = wifi_get_mibname(wl_ifname, "web_ofdma", mib_name);
  GetValue(mibname, web_ofdma_en);
  if ( strstr(v9, "ax") )
  {
    v9 = "bgn+ac+ax";
    SetValue("2.4_nettype", "bgn+ac+ax");
    if ( !strcmp(web_ofdma_en, "1") )
    {
      v11 = wifi_get_mibname(wl_ifname, "ofdma_mode", mib_name);
      v12 = "5";
    }
    else
    {
      v11 = wifi_get_mibname(wl_ifname, "ofdma_mode", mib_name);
      v12 = "2";
    }
  }
  else
  {
    SetValue("2.4_nettype", v9);
    v11 = wifi_get_mibname(wl_ifname, "ofdma_mode", mib_name);
    v12 = "0";
  }
  SetValue(v11, v12);
  v13 = v8 == 0;
  if ( v8 )
    v13 = Var == 0;
  if ( v13 )
    return 1;
  if ( !strcmp(Var, "auto") )
    strcpy(Var, "0");
  v15 = wifi_get_mibname(wl_ifname, "channel", wl_buf);
  GetValue(v15, mib_channel_24);
  v16 = wifi_get_mibname(wl_ifname, "bandwidth", wl_buf);
  GetValue(v16, mib_band_24);
  v17 = wifi_get_mibname(wl_ifname, "nettype", wl_buf);
  GetValue(v17, mib_mode);
  if ( strcmp(Var, mib_band_24) || strcmp(v8, mib_channel_24) || (result = strcmp(v9, mib_mode)) != 0 )
  {
    *wl2g_restart = 1;
    memset(s, 0, sizeof(s));
    memset(v32, 0, sizeof(v32));
    memset(v34, 0, 0x100u);
    v18 = wifi_get_mibname(wl_ifname, "countrycode", wl_buf);
    GetValue(v18, v32);
    if ( strcmp(Var, "20") && (v19 = atoi(v8)) != 0 )
    {
      if ( v19 <= 5 )
        v20 = "upper";
      else
        v20 = "lower";
    }
    else
    {
      v20 = "none";
    }
    strcpy(s, v20);
    memset(wl_buf->mib_buf, 0, wl_buf->max_length);
    memset(v34, 0, 0x100u);
    v21 = wifi_get_mibname(wl_ifname, "workmode", v34);
    GetValue(v21, wl_buf->mib_buf);
    v22 = wifi_get_mibname(wl_ifname, "bandwidth", v34);
    SetValue(v22, Var);
    v23 = wifi_get_mibname(wl_ifname, "channel", v34);
    SetValue(v23, v8);
    v24 = wifi_get_mibname(wl_ifname, "sideband_flag", v34);
    SetValue(v24, s);
    v25 = wifi_get_mibname(wl_ifname, "nettype", v34);
    SetValue(v25, v9);
    return 0;
  }
  return result;
}
