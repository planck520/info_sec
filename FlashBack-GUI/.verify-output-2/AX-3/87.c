/* =====================================================
 *  Path 87
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - getAdvanceStatus (arg=1, call_ea=0x31e20, func_ea=0x31d38, label=certain)
 *        call: GetValue("dhcps.en", mib_value);
 *    - fromDhcpSetSer (arg=1, call_ea=0x5274c, func_ea=0x52634, label=needs_check)
 *        call: SetValue("dhcps.en", Var);
 *    - websGetVar (arg=ret, call_ea=0x5268c, func_ea=source, label=source)
 *        call: Var = websGetVar(wp, "dhcpEn", "0");
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


/* Function: fromDhcpSetSer @ 0x52634 */
void __fastcall fromDhcpSetSer(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r7
  char_t *v5; // r10
  char_t *v6; // r9
  char_t *v7; // r0
  bool v8; // zf
  bool v9; // zf
  const char *v10; // r8
  int v11; // r2
  int v12; // r0
  int v13; // r0
  char_t olden[8]; // [sp+0h] [bp-190h] BYREF
  char dhcps_lease_time[32]; // [sp+8h] [bp-188h] BYREF
  char ret_buf[64]; // [sp+28h] [bp-168h] BYREF
  char param_str[256]; // [sp+68h] [bp-128h] BYREF

  memset(dhcps_lease_time, 0, sizeof(dhcps_lease_time));
  memset(ret_buf, 0, sizeof(ret_buf));
  Var = websGetVar(wp, "dhcpEn", "0");
  v5 = websGetVar(wp, "startIp", &byte_794DF);
  v6 = websGetVar(wp, "endIp", &byte_794DF);
  v7 = websGetVar(wp, "lease", &byte_794DF);
  v8 = v5 == 0;
  if ( v5 )
    v8 = Var == 0;
  if ( v8 )
    goto LABEL_11;
  v9 = v7 == 0;
  if ( v7 )
    v9 = v6 == 0;
  v10 = v7;
  if ( v9 )
  {
LABEL_11:
    v11 = -1;
  }
  else
  {
    GetValue("dhcps.en", olden);
    if ( atoi(olden) || atoi(Var) )
    {
      v12 = atoi(v10);
      sprintf(dhcps_lease_time, "%d", 3600 * v12);
      SetValue("dhcps.en", Var);
      SetValue("dhcps.start", v5);
      SetValue("dhcps.end", v6);
      SetValue("dhcps.leasetime", dhcps_lease_time);
      memset(param_str, 0, sizeof(param_str));
      sprintf(param_str, "op=%d,index=0", 3);
      v13 = send_msg_to_netctrl(3, param_str);
      CommitCfm(v13);
      v11 = 0;
    }
    else
    {
      v11 = 0;
    }
  }
  sprintf(ret_buf, "{\"errCode\":%d}", v11);
  websTransfer(wp, ret_buf);
}
