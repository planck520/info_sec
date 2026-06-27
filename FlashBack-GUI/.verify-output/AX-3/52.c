/* =====================================================
 *  Path 52
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formWifiRadioGet_5G (arg=1, call_ea=0x3501c, func_ea=0x34e04, label=certain)
 *        call: GetValue("5_nettype", web_nettype);
 *    - formWifiRadioSet_5G (arg=1, call_ea=0x35840, func_ea=0x35680, label=needs_check)
 *        call: SetValue("5_nettype", v13);
 *    - websGetVar (arg=ret, call_ea=0x35764, func_ea=source, label=source)
 *        call: v9 = websGetVar(wp, "adv_mode_5g", "an+ac");
 * ===================================================== */


/* Function: formWifiRadioGet_5G @ 0x34E04 */
void __fastcall formWifiRadioGet_5G(cJSON_0 *root, char *wl_ifname)
{
  cJSON *String; // r0
  cJSON *v5; // r0
  int mibname; // r0
  cJSON *v7; // r0
  cJSON *v8; // r0
  cJSON *Object; // r8
  int v10; // r0
  cJSON *Array; // r5
  cJSON *v12; // r5
  cJSON *v13; // r4
  channel_list_inparam_t wifi_5g_inparam; // [sp+24h] [bp-D8h] BYREF
  char ifname[16]; // [sp+30h] [bp-CCh] BYREF
  char os_ifname[16]; // [sp+40h] [bp-BCh] BYREF
  char web_nettype[16]; // [sp+50h] [bp-ACh] BYREF
  chan_info_t chan_info; // [sp+60h] [bp-9Ch] BYREF
  channel_list_t channel_list; // [sp+78h] [bp-84h] BYREF
  char wifi_band_value[256]; // [sp+FCh] [bp+0h] BYREF
  char wifi_countrycode[256]; // [sp+1FCh] [bp+100h] BYREF
  char mib_name[256]; // [sp+2FCh] [bp+200h] BYREF
  WIFI_BUF wifi_buf_enty; // [sp+3FCh] [bp+300h] BYREF

  memset(ifname, 0, sizeof(ifname));
  memset(os_ifname, 0, sizeof(os_ifname));
  memset(wifi_band_value, 0, sizeof(wifi_band_value));
  memset(wifi_countrycode, 0, sizeof(wifi_countrycode));
  memset(mib_name, 0, sizeof(mib_name));
  memset(web_nettype, 0, sizeof(web_nettype));
  memset(&channel_list, 0, sizeof(channel_list));
  memset(&wifi_buf_enty, 0, sizeof(wifi_buf_enty));
  wifi_buf_enty.max_length = 256;
  *(_DWORD *)wifi_5g_inparam.country = 0;
  memset(&chan_info, 0, sizeof(chan_info));
  sprintf(ifname, "%s.0", wl_ifname);
  tpi_wifi_get_osifname(ifname, os_ifname);
  tpi_wifi_get_chaninfo(os_ifname, &chan_info);
  String = cJSON_CreateString(chan_info.bandwidth);
  cJSON_AddItemToObject((cJSON *)root, "adv_current_band_5g", String);
  v5 = cJSON_CreateString(chan_info.channel);
  cJSON_AddItemToObject((cJSON *)root, "adv_current_channel_5g", v5);
  get_index_mib_2cJSONString(root, "adv_channel_5g", wl_ifname, "channel", &wifi_buf_enty);
  mibname = wifi_get_mibname(wl_ifname, "bandwidth", mib_name);
  GetValue(mibname, wifi_band_value);
  if ( !strcmp(wifi_band_value, "0") )
    strcpy(wifi_band_value, "auto");
  v7 = cJSON_CreateString(wifi_band_value);
  cJSON_AddItemToObject((cJSON *)root, "adv_band_5g", v7);
  get_index_mib_2cJSONString(root, "adv_extend_channel_5g", wl_ifname, "sideband_flag", &wifi_buf_enty);
  GetValue("5_nettype", web_nettype);
  v8 = cJSON_CreateString(web_nettype);
  cJSON_AddItemToObject((cJSON *)root, "adv_mode_5g", v8);
  get_index_mib_2cJSONString(root, "adv_country_5g", wl_ifname, "countrycode", &wifi_buf_enty);
  Object = cJSON_CreateObject();
  cJSON_AddItemToObject((cJSON *)root, "channel_5g", Object);
  v10 = wifi_get_mibname(wl_ifname, "countrycode", mib_name);
  GetValue(v10, wifi_countrycode);
  strcpy(wifi_5g_inparam.country, wifi_countrycode);
  memset(&channel_list, 0, sizeof(channel_list));
  tpi_wifi_get_channel_list_by_country(os_ifname, 20, 0, *(_DWORD *)wifi_5g_inparam.country, &channel_list);
  if ( channel_list.num > 0 )
  {
    Array = cJSON_CreateArray();
    cJSON_AddItemToObject(Object, "20", Array);
    assembleChannelList2JsonArray((cJSON_0 *)Array, channel_list.channel, channel_list.num);
  }
  memset(&channel_list, 0, sizeof(channel_list));
  tpi_wifi_get_channel_list_by_country(os_ifname, 40, 0, *(_DWORD *)wifi_5g_inparam.country, &channel_list);
  if ( channel_list.num > 0 )
  {
    v12 = cJSON_CreateArray();
    cJSON_AddItemToObject(Object, "40", v12);
    assembleChannelList2JsonArray((cJSON_0 *)v12, channel_list.channel, channel_list.num);
  }
  memset(&channel_list, 0, sizeof(channel_list));
  tpi_wifi_get_channel_list_by_country(os_ifname, 80, 0, *(_DWORD *)wifi_5g_inparam.country, &channel_list);
  if ( channel_list.num > 0 )
  {
    v13 = cJSON_CreateArray();
    cJSON_AddItemToObject(Object, "80", v13);
    assembleChannelList2JsonArray((cJSON_0 *)v13, channel_list.channel, channel_list.num);
  }
}


/* Function: formWifiRadioSet_5G @ 0x35680 */
int __fastcall formWifiRadioSet_5G(webs_t wp, WIFI_BUF *wl_buf, char *wl_ifname, int *wl5g_restart)
{
  char *Var; // r7
  char_t *v8; // r6
  char_t *v9; // r0
  bool v10; // zf
  int v11; // r3
  int result; // r0
  const char *v13; // r5
  int mibname; // r0
  int v15; // r0
  char *v16; // r1
  int v17; // r0
  int v18; // r0
  int v19; // r0
  int v20; // r0
  const char *v21; // r1
  char *v22; // r3
  char *v23; // r3
  int v24; // r10
  int v25; // r0
  int v26; // r0
  int v27; // r0
  int v28; // r0
  int v29; // r0
  int v30; // r0
  char *s2; // [sp+0h] [bp-2E0h]
  char *s2a; // [sp+0h] [bp-2E0h]
  char web_ofdma_en[8]; // [sp+10h] [bp-2D0h] BYREF
  char mib_channel_5[32]; // [sp+18h] [bp-2C8h] BYREF
  char mib_band_5[32]; // [sp+38h] [bp-2A8h] BYREF
  char mib_country_5g[32]; // [sp+58h] [bp-288h] BYREF
  char mib_mode_5g[32]; // [sp+78h] [bp-268h] BYREF
  char s[32]; // [sp+98h] [bp-248h] BYREF
  char mib_name[256]; // [sp+B8h] [bp-228h] BYREF
  _BYTE v41[296]; // [sp+1B8h] [bp-128h] BYREF

  memset(mib_channel_5, 0, sizeof(mib_channel_5));
  memset(mib_band_5, 0, sizeof(mib_band_5));
  memset(mib_country_5g, 0, sizeof(mib_country_5g));
  memset(mib_mode_5g, 0, sizeof(mib_mode_5g));
  memset(mib_name, 0, sizeof(mib_name));
  memset(web_ofdma_en, 0, sizeof(web_ofdma_en));
  Var = websGetVar(wp, "adv_band_5g", "40");
  v8 = websGetVar(wp, "adv_channel_5g", "0");
  v9 = websGetVar(wp, "adv_mode_5g", "an+ac");
  v10 = v8 == 0;
  if ( v8 )
    v10 = Var == 0;
  v11 = v10;
  if ( !v9 )
    v11 |= 1u;
  if ( v11 )
    return 1;
  v13 = v9;
  mibname = wifi_get_mibname(wl_ifname, "web_ofdma", mib_name);
  GetValue(mibname, web_ofdma_en);
  if ( strstr(v13, "ax") )
  {
    v13 = "an+ac+ax";
    SetValue("5_nettype", "an+ac+ax");
    if ( !strcmp(web_ofdma_en, "1") )
    {
      v15 = wifi_get_mibname(wl_ifname, "ofdma_mode", mib_name);
      v16 = "5";
    }
    else
    {
      v15 = wifi_get_mibname(wl_ifname, "ofdma_mode", mib_name);
      v16 = "2";
    }
  }
  else
  {
    SetValue("5_nettype", v13);
    v15 = wifi_get_mibname(wl_ifname, "ofdma_mode", mib_name);
    v16 = "0";
  }
  SetValue(v15, v16);
  if ( !strcmp(Var, "auto") )
    strcpy(Var, "0");
  v17 = wifi_get_mibname(wl_ifname, "channel", wl_buf);
  GetValue(v17, mib_channel_5);
  v18 = wifi_get_mibname(wl_ifname, "bandwidth", wl_buf);
  GetValue(v18, mib_band_5);
  v19 = wifi_get_mibname(wl_ifname, "countrycode", wl_buf);
  GetValue(v19, mib_country_5g);
  v20 = wifi_get_mibname(wl_ifname, "nettype", wl_buf);
  GetValue(v20, mib_mode_5g);
  if ( strcmp(Var, mib_band_5) || strcmp(v8, mib_channel_5) || (result = strcmp(v13, mib_mode_5g)) != 0 )
  {
    *wl5g_restart = 1;
    memset(s, 0, sizeof(s));
    memset(v41, 0, 0x100u);
    if ( !strcmp(Var, "20") || !strcmp(Var, "80") || !atoi(v8) )
      goto LABEL_21;
    strcpy(s, "none");
    v22 = 0;
    do
    {
      s2 = v22;
      if ( wifi_band_upper[(_DWORD)v22] == atoi(v8) )
      {
        v21 = "upper";
        goto LABEL_31;
      }
      v22 = s2 + 1;
    }
    while ( s2 != (char *)4 );
    v23 = 0;
    do
    {
      s2a = v23;
      if ( wifi_band_lower[(_DWORD)v23] == atoi(v8) )
      {
        v21 = "lower";
        goto LABEL_31;
      }
      v23 = s2a + 1;
    }
    while ( s2a != (char *)5 );
    v24 = wifi_band_none[0];
    v25 = atoi(v8);
    if ( v24 == v25 || v25 == wifi_band_none[1] )
    {
LABEL_21:
      v21 = "none";
LABEL_31:
      strcpy(s, v21);
    }
    memset(wl_buf->mib_buf, 0, wl_buf->max_length);
    memset(v41, 0, 0x100u);
    v26 = wifi_get_mibname(wl_ifname, "workmode", v41);
    GetValue(v26, wl_buf->mib_buf);
    v27 = wifi_get_mibname(wl_ifname, "bandwidth", v41);
    SetValue(v27, Var);
    v28 = wifi_get_mibname(wl_ifname, "channel", v41);
    SetValue(v28, v8);
    v29 = wifi_get_mibname(wl_ifname, "sideband_flag", v41);
    SetValue(v29, s);
    v30 = wifi_get_mibname(wl_ifname, "nettype", v41);
    SetValue(v30, v13);
    return 0;
  }
  return result;
}
