/* =====================================================
 *  Path 113
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - form_fast_setting_get (arg=1, call_ea=0x2c9a0, func_ea=0x2c188, label=certain)
 *        call: GetValue("wan1.mac.clone.type", mib_value);
 *    - form_fast_setting_internet_set (arg=1, call_ea=0x2d330, func_ea=0x2d098, label=certain)
 *        call: SetValue("wan1.mac.clone.type", v8);
 *    - websGetVar (arg=ret, call_ea=0x2d2fc, func_ea=source, label=source)
 *        call: v8 = websGetVar(wp, "cloneType", "0");
 * ===================================================== */


/* Function: form_fast_setting_get @ 0x2C188 */
void __fastcall form_fast_setting_get(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Object; // r5
  int v5; // r1
  int v6; // r2
  int v7; // r3
  int v8; // r0
  int port_link_status; // r0
  int v10; // r7
  int uptime; // r0
  int v12; // r0
  int v13; // r1
  int v14; // r2
  int v15; // r3
  int v16; // r0
  double v17; // r0
  cJSON *Number; // r0
  time_t v19; // r11
  int mibname; // r0
  int v21; // r0
  cJSON *v22; // r0
  cJSON *v23; // r0
  cJSON *v24; // r0
  cJSON *String; // r2
  cJSON *v26; // r0
  cJSON *v27; // r0
  cJSON *v28; // r0
  cJSON *v29; // r0
  cJSON *v30; // r0
  cJSON *v31; // r0
  const char *v32; // r8
  cJSON *v33; // r0
  cJSON *v34; // r0
  cJSON *v35; // r0
  cJSON *v36; // r0
  cJSON *v37; // r0
  int v38; // r0
  cJSON *v39; // r0
  int v40; // r0
  cJSON *v41; // r0
  int v42; // r0
  cJSON *v43; // r0
  int v44; // r0
  cJSON *v45; // r0
  int v46; // r0
  cJSON *v47; // r0
  int v48; // r0
  cJSON *v49; // r0
  int v50; // r0
  cJSON *v51; // r2
  cJSON *v52; // r0
  cJSON *v53; // r0
  cJSON *v54; // r0
  cJSON *v55; // r0
  char *v56; // r4
  char s[32]; // [sp+8h] [bp-348h] BYREF
  char mib_value[256]; // [sp+28h] [bp-328h] BYREF
  char mib_name[256]; // [sp+128h] [bp-228h] BYREF
  _DWORD v60[74]; // [sp+228h] [bp-128h] BYREF

  memset(mib_value, 0, sizeof(mib_value));
  memset(mib_name, 0, sizeof(mib_name));
  Object = cJSON_CreateObject();
  v8 = wanid_to_phy_port(1, v5, v6, v7);
  port_link_status = get_port_link_status(v8);
  v10 = port_link_status;
  if ( port_link_status )
  {
    uptime = system_get_uptime(port_link_status);
    v10 = uptime;
    if ( !fistTime_12289 )
      fistTime_12289 = uptime;
  }
  else
  {
    fistTime_12289 = 0;
    sleep(1u);
  }
  v60[0] = 0;
  v60[1] = 0;
  if ( GetValue("wan.detecttype", v60) && atoi((const char *)v60) == 1 )
  {
    want_12250 = -2;
  }
  else if ( !GetValue("wan.detecttype", v60) || (v12 = atoi((const char *)v60), v12 == 5) )
  {
    want_12250 = -1;
    net = 0;
  }
  else
  {
    want_12250 = v12;
  }
  wanType = want_12250;
  printf("----%s---%d----wanType = %d-----\n", "form_fast_setting_get", 242, want_12250);
  if ( wanType != -1 )
    net = 1;
  printf("sysTime:%d fistTime:%d  net:%d\n", v10, fistTime_12289, net);
  v16 = wanid_to_phy_port(1, v13, v14, v15);
  v17 = (double)get_port_link_status(v16);
  Number = cJSON_CreateNumber(v17);
  cJSON_AddItemToObject(Object, "line", Number);
  v19 = fistTime_12289;
  memset(s, 0, sizeof(s));
  memset(v60, 0, 0x100u);
  if ( tpi_wifi_get_mibif_band("wlan0") == 2 )
  {
    mibname = wifi_get_mibname("wlan0", "countrycode", v60);
    GetValue(mibname, s);
  }
  if ( tpi_wifi_get_mibif_band("wlan1") == 2 )
  {
    v21 = wifi_get_mibname("wlan1", "countrycode", v60);
    GetValue(v21, s);
  }
  if ( !strcmp(s, "RU") || !strcmp(s, "UA") )
  {
    puts("COUNTRY CODE RU or UA");
    v22 = cJSON_CreateNumber(-2.0);
    cJSON_AddItemToObject(Object, "wanType", v22);
    v23 = cJSON_CreateNumber(1.0);
    cJSON_AddItemToObject(Object, "net", v23);
    v24 = cJSON_CreateNumber(0.0);
    cJSON_AddItemToObject(Object, "outType", v24);
    String = cJSON_CreateString("0");
  }
  else if ( net == 1 || v10 - v19 <= 29 )
  {
    puts("##########check ok or not timeout ##########");
    v26 = cJSON_CreateNumber((double)wanType);
    cJSON_AddItemToObject(Object, "wanType", v26);
    v27 = cJSON_CreateNumber((double)net);
    cJSON_AddItemToObject(Object, "net", v27);
    v28 = cJSON_CreateNumber(1.0);
    cJSON_AddItemToObject(Object, "outType", v28);
    String = cJSON_CreateString("0");
  }
  else
  {
    puts("~~~~~~~~~~ check time out ~~~~~~~~~~");
    v29 = cJSON_CreateNumber(-2.0);
    cJSON_AddItemToObject(Object, "wanType", v29);
    v30 = cJSON_CreateNumber(1.0);
    cJSON_AddItemToObject(Object, "net", v30);
    v31 = cJSON_CreateNumber(0.0);
    cJSON_AddItemToObject(Object, "outType", v31);
    String = cJSON_CreateString("1");
  }
  cJSON_AddItemToObject(Object, "timeout", String);
  v32 = "wlan0";
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("lan.ip", mib_value);
  v33 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "lanIp", v33);
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("lan.mask", mib_value);
  v34 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "lanMask", v34);
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("wan1.ppoe.userid", mib_value);
  v35 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "adslUser", v35);
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("wan1.ppoe.pwd", mib_value);
  v36 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "adslPwd", v36);
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("wlan0_ssid5g_prio", mib_value);
  v37 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "doubleBand", v37);
  if ( tpi_wifi_get_mibif_band("wlan0") == 2 )
  {
    memset(mib_value, 0, sizeof(mib_value));
    v38 = wifi_get_mibname("wlan0.0", "bss_ssid", mib_name);
    GetValue(v38, mib_value);
    v39 = cJSON_CreateString(mib_value);
    cJSON_AddItemToObject(Object, "ssid", v39);
    memset(mib_value, 0, sizeof(mib_value));
    v40 = wifi_get_mibname("wlan0.0", "bss_wpapsk_key", mib_name);
    GetValue(v40, mib_value);
    v41 = cJSON_CreateString(mib_value);
    cJSON_AddItemToObject(Object, "wrlPassword", v41);
    memset(mib_value, 0, sizeof(mib_value));
    v42 = wifi_get_mibname("wlan0", "countrycode", mib_name);
    GetValue(v42, mib_value);
    v43 = cJSON_CreateString(mib_value);
    cJSON_AddItemToObject(Object, "countryCode", v43);
    memset(mib_value, 0, sizeof(mib_value));
  }
  else
  {
    v32 = "wlan1";
    if ( tpi_wifi_get_mibif_band("wlan1") != 2 )
      goto LABEL_30;
    memset(mib_value, 0, sizeof(mib_value));
    v44 = wifi_get_mibname("wlan1.0", "bss_ssid", mib_name);
    GetValue(v44, mib_value);
    v45 = cJSON_CreateString(mib_value);
    cJSON_AddItemToObject(Object, "ssid", v45);
    memset(mib_value, 0, sizeof(mib_value));
    v46 = wifi_get_mibname("wlan1.0", "bss_wpapsk_key", mib_name);
    GetValue(v46, mib_value);
    v47 = cJSON_CreateString(mib_value);
    cJSON_AddItemToObject(Object, "wrlPassword", v47);
    memset(mib_value, 0, sizeof(mib_value));
    v48 = wifi_get_mibname("wlan1", "countrycode", mib_name);
    GetValue(v48, mib_value);
    v49 = cJSON_CreateString(mib_value);
    cJSON_AddItemToObject(Object, "countryCode", v49);
    memset(mib_value, 0, sizeof(mib_value));
  }
  v50 = wifi_get_mibname(v32, "power", mib_name);
  GetValue(v50, mib_value);
LABEL_30:
  if ( !strcmp(mib_value, "high") )
    v51 = cJSON_CreateString("high");
  else
    v51 = cJSON_CreateString("low");
  cJSON_AddItemToObject(Object, "power", v51);
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("wan1.mac.clone.type", mib_value);
  v52 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "cloneType", v52);
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("wan1.macaddr", mib_value);
  v53 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "mac", v53);
  memset(mib_value, 0, sizeof(mib_value));
  get_ip_from_mac(wp->ipaddr, mib_value);
  v54 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "deviceMac", v54);
  memset(mib_value, 0, sizeof(mib_value));
  get_wan_fact_mac(1, mib_value);
  v55 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "defMac", v55);
  v56 = cJSON_Print(Object);
  cJSON_Delete(Object);
  websTransfer(wp, v56);
  printf("json string: %s \n\n", v56);
  free(v56);
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
