/* =====================================================
 *  Path 89
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - getAdvanceStatus (arg=1, call_ea=0x32328, func_ea=0x31d38, label=needs_check)
 *        call: GetValue("wan1.dmzip", mib_value);
 *    - mDMZSetCfg (arg=1, call_ea=0x4d4d4, func_ea=0x4d400, label=needs_check)
 *        call: v10 = SetValue("wan1.dmzip", v8);
 *    - websGetVar (arg=ret, call_ea=0x4d464, func_ea=source, label=source)
 *        call: v5 = websGetVar(wp, "dmzIp", &byte_794DF);
 * ===================================================== */


/* Function: getAdvanceStatus @ 0x31D38 */
void __fastcall getAdvanceStatus(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Object; // r5
  void *v5; // r0
  int lan_ifname; // r0
  cJSON *String; // r0
  cJSON *v8; // r0
  cJSON *v9; // r0
  int v10; // r0
  const char *v11; // r0
  cJSON *v12; // r0
  int mibname; // r0
  int v14; // r0
  cJSON *v15; // r2
  int v16; // r0
  const char *v17; // r0
  int v18; // r0
  int v19; // r0
  int v20; // r0
  int v21; // r0
  int v22; // r0
  int v23; // r0
  int v24; // r0
  const char *eth_name; // r0
  const char *v26; // r1
  const char *v27; // r1
  cJSON *v28; // r0
  cJSON *v29; // r0
  cJSON *v30; // r0
  cJSON *v31; // r0
  cJSON *v32; // r0
  int v33; // r0
  cJSON *v34; // r2
  int v35; // r0
  char *v36; // r4
  char_t *fmt; // [sp+0h] [bp-670h]
  int v38; // [sp+Ch] [bp-664h] BYREF
  _DWORD v39[2]; // [sp+10h] [bp-660h] BYREF
  _DWORD v40[4]; // [sp+18h] [bp-658h] BYREF
  _DWORD v41[8]; // [sp+28h] [bp-648h] BYREF
  char mib_value[256]; // [sp+48h] [bp-628h] BYREF
  char mib_name[256]; // [sp+148h] [bp-528h] BYREF
  char connectType[256]; // [sp+248h] [bp-428h] BYREF
  char wanMTU[256]; // [sp+348h] [bp-328h] BYREF
  char v46[256]; // [sp+448h] [bp-228h] BYREF
  _BYTE v47[296]; // [sp+548h] [bp-128h] BYREF

  memset(mib_value, 0, sizeof(mib_value));
  memset(mib_name, 0, sizeof(mib_name));
  memset(connectType, 0, sizeof(connectType));
  memset(wanMTU, 0, sizeof(wanMTU));
  Object = cJSON_CreateObject();
  v5 = memset(mib_value, 0, sizeof(mib_value));
  lan_ifname = ifaddrs_get_lan_ifname(v5);
  if ( ifaddrs_get_ifip(lan_ifname, mib_value) < 0 )
  {
    memset(mib_value, 0, sizeof(mib_value));
    GetValue("lan.ip", mib_value);
  }
  String = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "lanIp", String);
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("dhcps.en", mib_value);
  v8 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "dhcp", v8);
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("wan1.mac.clone.en", mib_value);
  if ( atoi(mib_value) )
  {
    memset(mib_value, 0, sizeof(mib_value));
    GetValue("wan1.macaddr", mib_value);
  }
  v9 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "mac", v9);
  GetValue("wan1.connecttype", connectType);
  v10 = atoi(connectType);
  if ( v10 == 1 )
  {
    v11 = "wan1.staticMTU";
  }
  else if ( v10 == 2 )
  {
    v11 = "wan1.ppoe.mtu";
  }
  else
  {
    if ( v10 )
    {
      strcpy(wanMTU, "1500");
      goto LABEL_13;
    }
    v11 = "wan1.dynamicMTU";
  }
  GetValue(v11, wanMTU);
LABEL_13:
  v12 = cJSON_CreateString(wanMTU);
  cJSON_AddItemToObject(Object, "mtu", v12);
  memset(v47, 0, 0x100u);
  v40[0] = 0;
  v40[1] = 0;
  v41[0] = 0;
  v41[1] = 0;
  memset(v46, 0, sizeof(v46));
  mibname = wifi_get_mibname("wlan0.0", "bss_enable", v47);
  GetValue(mibname, v40);
  v14 = wifi_get_mibname("wlan1.0", "bss_enable", v47);
  GetValue(v14, v41);
  if ( atoi((const char *)v40) || atoi((const char *)v41) )
  {
    memset(v46, 0, sizeof(v46));
    v16 = wifi_get_mibname("wlan0", "power", v47);
    GetValue(v16, v46);
    if ( !strcmp("low", v46) )
    {
      v17 = "1";
    }
    else if ( !strcmp("middle", v46) )
    {
      v17 = "2";
    }
    else if ( !strcmp("high", v46) )
    {
      v17 = "3";
    }
    else
    {
      v17 = "0";
    }
    v15 = cJSON_CreateString(v17);
  }
  else
  {
    v15 = cJSON_CreateString("0");
  }
  cJSON_AddItemToObject(Object, "power", v15);
  memset(v47, 0, 0x100u);
  v39[0] = 0;
  v39[1] = 0;
  memset(v41, 0, sizeof(v41));
  memset(v40, 0, sizeof(v40));
  v38 = 0;
  memset(v46, 0, sizeof(v46));
  GetValue("wl.extra_chkHz", &v38);
  if ( atoi((const char *)&v38) )
  {
    v18 = wifi_get_mibname("wlan1", "workmode", v47);
    GetValue(v18, v46);
    v19 = wifi_get_mibname("wlan1", "enable", v47);
    GetValue(v19, v39);
    v20 = wifi_get_mibname("wlan1.x", "extend_mac", v47);
    GetValue(v20, v41);
    v21 = 24;
  }
  else
  {
    v22 = wifi_get_mibname("wlan0", "workmode", v47);
    GetValue(v22, v46);
    v23 = wifi_get_mibname("wlan0", "enable", v47);
    GetValue(v23, v39);
    v24 = wifi_get_mibname("wlan0.x", "extend_mac", v47);
    GetValue(v24, v41);
    v21 = 20;
  }
  eth_name = (const char *)get_eth_name(v21);
  strcpy((char *)v40, eth_name);
  if ( strcmp(v46, "ap") && atoi((const char *)v39) )
    v26 = "1";
  else
    v26 = "0";
  strcpy(v46, v26);
  if ( atoi(v46) )
  {
    memset(v46, 0, sizeof(v46));
    if ( tpi_wifi_get_extend_state(v40) == 4 )
      v27 = "2";
    else
      v27 = "1";
    strcpy(v46, v27);
  }
  v28 = cJSON_CreateString(v46);
  cJSON_AddItemToObject(Object, "wisp", v28);
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("wan1.dmzen", mib_value);
  if ( atoi(mib_value) )
  {
    memset(mib_value, 0, sizeof(mib_value));
    GetValue("wan1.dmzip", mib_value);
  }
  v29 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "dmz", v29);
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("dns.check.enable_s", mib_value);
  v30 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "yun", v30);
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("qos.auto.en", mib_value);
  v31 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "qos", v31);
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("ucloud.en", mib_value);
  v32 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "ucloud", v32);
  memset(mib_value, 0, sizeof(mib_value));
  v33 = wifi_get_mibname("wlan0", "workmode", mib_name);
  if ( GetValue(v33, mib_value) && mib_value[0] )
  {
    v34 = cJSON_CreateString(mib_value);
  }
  else
  {
    v35 = wifi_get_mibname("wlan1", "workmode", mib_name);
    GetValue(v35, mib_value);
    v34 = cJSON_CreateString(mib_value);
  }
  cJSON_AddItemToObject(Object, "wl_mode", v34);
  v36 = cJSON_Print(Object);
  cJSON_Delete(Object);
  websWrite(wp, mib_name);
  websWrite(wp, fmt);
  free(v36);
  websDone(wp, 200);
}


/* Function: mDMZSetCfg @ 0x4D400 */
void __fastcall mDMZSetCfg(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r9
  char_t *v5; // r0
  bool v6; // zf
  int v7; // r2
  const char *v8; // r5
  in_addr_t v9; // r11
  int v10; // r0
  char_t lanip[16]; // [sp+0h] [bp-10h] BYREF
  char ret_buf[64]; // [sp+10h] [bp+0h] BYREF
  char param_str[260]; // [sp+50h] [bp+40h] BYREF

  memset(param_str, 0, 0x100u);
  memset(ret_buf, 0, sizeof(ret_buf));
  Var = websGetVar(wp, "dmzEn", "0");
  v5 = websGetVar(wp, "dmzIp", &byte_794DF);
  v6 = v5 == 0;
  if ( v5 )
    v6 = Var == 0;
  if ( !v6 )
  {
    v8 = v5;
    GetValue("lan.ip", lanip);
    v9 = inet_addr(v8);
    if ( v9 == inet_addr(lanip) )
    {
      v7 = 2;
      goto out;
    }
    SetValue("wan1.dmzen", Var);
    v10 = SetValue("wan1.dmzip", v8);
    if ( CommitCfm(v10) )
    {
      sprintf(param_str, "advance_type=%d", 1);
      send_msg_to_netctrl(5, param_str);
      v7 = 0;
      goto out;
    }
  }
  v7 = 1;
out:
  sprintf(ret_buf, "{\"errCode\":%d}", v7);
  websTransfer(wp, ret_buf);
}
