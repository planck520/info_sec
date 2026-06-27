/* =====================================================
 *  Path 88
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - getAdvanceStatus (arg=1, call_ea=0x31e8c, func_ea=0x31d38, label=needs_check)
 *        call: GetValue("wan1.macaddr", mib_value);
 *    - form_fast_setting_internet_set (arg=1, call_ea=0x2d3cc, func_ea=0x2d098, label=needs_check)
 *        call: v10 = SetValue("wan1.macaddr", v12);
 *    - websGetVar (arg=ret, call_ea=0x2d318, func_ea=source, label=source)
 *        call: v9 = websGetVar(wp, "mac", &byte_794DF);
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


/* Function: form_fast_setting_internet_set @ 0x2D098 */
void __fastcall form_fast_setting_internet_set(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r6
  UGW_WAN_CONNECT_TYPE_ENUM v5; // r8
  _BOOL4 v6; // r7
  int v7; // r6
  char_t *v8; // r8
  char_t *v9; // r11
  int v10; // r0
  char v11; // r8
  char *v12; // r1
  int v13; // r6
  int v14; // r5
  int WanConnType; // [sp+8h] [bp-208h]
  _BYTE s[24]; // [sp+10h] [bp-200h] BYREF
  char ret_buf[64]; // [sp+28h] [bp-1E8h] BYREF
  char connType_Old_Value[64]; // [sp+68h] [bp-1A8h] BYREF
  char pppoe_user_passwd_change[64]; // [sp+A8h] [bp-168h] BYREF
  char param_str[256]; // [sp+E8h] [bp-128h] BYREF

  memset(ret_buf, 0, sizeof(ret_buf));
  memset(connType_Old_Value, 0, sizeof(connType_Old_Value));
  memset(pppoe_user_passwd_change, 0, sizeof(pppoe_user_passwd_change));
  WanConnType = getWanConnType(1);
  Var = websGetVar(wp, "netWanType", "0");
  v5 = atoi(Var);
  if ( getWanValue(1, "connecttype", connType_Old_Value, 64) )
    v6 = 0;
  else
    v6 = v5 != atoi(connType_Old_Value);
  if ( v5 )
  {
    switch ( v5 )
    {
      case UGW_WAN_CONNECT_TYPE::UGW_WAN_CONNECT_STATIC:
        setWanValue(1, "connecttype", Var);
        setStaticConfig(wp, 1);
        break;
      case UGW_WAN_CONNECT_TYPE::UGW_WAN_CONNECT_PPPOE:
        setWanValue(1, "connecttype", Var);
        setPppoeConfig(wp, 1);
        if ( !getWanValue(1, "pppoe.auth.changed", pppoe_user_passwd_change, 64) )
        {
          v7 = atoi(pppoe_user_passwd_change);
          goto LABEL_18;
        }
        break;
      case UGW_WAN_CONNECT_TYPE::UGW_WAN_CONNECT_PPPOE_DOUBLE:
        memset(param_str, 0, 0x10u);
        sprintf(param_str, "%d", 5);
        setWanValue(1, "connecttype", param_str);
        setDoublePppoeConfig(wp, 1);
        break;
      case UGW_WAN_CONNECT_TYPE::UGW_WAN_CONNECT_PPTP:
        setWanValue(1, "connecttype", Var);
        setDoublePptpConfig(wp, 1);
        break;
      case UGW_WAN_CONNECT_TYPE::UGW_WAN_CONNECT_L2TP:
        setWanValue(1, "connecttype", Var);
        setDoubleL2tpConfig(wp, 1);
        break;
    }
  }
  else
  {
    setWanValue(1, "connecttype", Var);
    setDhcpConfig(wp, 1);
  }
  v7 = 0;
LABEL_18:
  if ( set_ipv6_configure(v5) == 1 )
    send_message_ipv6_changed();
  memset(s, 0, sizeof(s));
  memset(param_str, 0, 0x20u);
  v8 = websGetVar(wp, "cloneType", "0");
  v9 = websGetVar(wp, "mac", &byte_794DF);
  get_wan_fact_mac(1, s);
  SetValue("wan1.mac.clone.type", v8);
  if ( strcmp(v8, "0") )
  {
    if ( !strcmp(v8, "1") )
    {
      get_ip_from_mac(wp->ipaddr, param_str);
      v12 = param_str;
    }
    else
    {
      v10 = strcmp(v8, "2");
      if ( v10 )
      {
        v11 = 0;
        goto END;
      }
      v12 = v9;
    }
    v11 = 1;
    v10 = SetValue("wan1.macaddr", v12);
    goto END;
  }
  v10 = SetValue("wan1.macaddr", s);
  v11 = 0;
END:
  if ( CommitSyncCfm(v10) && (v7 == 1 ? (v13 = v6 | 1) : (v13 = v6), v13 | v11 & 1) )
  {
    doSystemCmd("echo \"0 0\" > /etc/conntime%d", 1);
    memset(param_str, 0, sizeof(param_str));
    sprintf(param_str, "op=%d,wan_id=%d,conn_type=%d", 3, 1, WanConnType);
    send_msg_to_netctrl(2, param_str);
    sprintf(param_str, "op=%d,wan_id=%d", 11, 1);
    send_msg_to_netctrl(2, param_str);
    v14 = 0;
  }
  else
  {
    v14 = 1;
  }
  doSystemCmd("rm -rf /etc/ppp/pppoe_auth_status.wan1 &");
  sprintf(ret_buf, "{\"errCode\":%d}", v14);
  websTransfer(wp, ret_buf);
}
