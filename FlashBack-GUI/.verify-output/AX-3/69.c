/* =====================================================
 *  Path 69
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - fromGetWirelessRepeat (arg=1, call_ea=0x3b5dc, func_ea=0x3b470, label=certain)
 *        call: GetValue("wl.extra_chkHz", wifi_chkHz);
 *    - fromSetWirelessRepeat (arg=1, call_ea=0x3ac98, func_ea=0x3a724, label=certain)
 *        call: SetValue("wl.extra_chkHz", nptr);
 *    - websGetVar (arg=ret, call_ea=0x3a800, func_ea=source, label=source)
 *        call: nptr = websGetVar(wp, "wifi_chkHz", "0");
 * ===================================================== */


/* Function: fromGetWirelessRepeat @ 0x3B470 */
void __fastcall fromGetWirelessRepeat(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Object; // r4
  cJSON *String; // r0
  cJSON *v5; // r0
  int mibname; // r0
  int v7; // r0
  const char *v8; // r1
  cJSON *v9; // r0
  int v10; // r0
  int v11; // r0
  const char *v12; // r1
  cJSON *v13; // r0
  cJSON *v14; // r0
  int wifi_status; // r0
  cJSON *v16; // r0
  bool v17; // zf
  char *v18; // r1
  char *v19; // r2
  char *v20; // r0
  char wifi_chkHz[4]; // [sp+14h] [bp-1Ch] BYREF
  int v23; // [sp+18h] [bp-18h] BYREF
  int v24; // [sp+1Ch] [bp-14h]
  int v25; // [sp+20h] [bp-10h] BYREF
  int v26; // [sp+24h] [bp-Ch]
  int v27; // [sp+28h] [bp-8h] BYREF
  int v28; // [sp+2Ch] [bp-4h]
  char wl2g_mib_radio[16]; // [sp+30h] [bp+0h] BYREF
  char wl5g_mib_radio[16]; // [sp+40h] [bp+10h] BYREF
  char wl2g_bss[16]; // [sp+50h] [bp+20h] BYREF
  char wl5g_bss[16]; // [sp+60h] [bp+30h] BYREF
  char wl2g_bss_guest[16]; // [sp+70h] [bp+40h] BYREF
  char wl5g_bss_guest[16]; // [sp+80h] [bp+50h] BYREF
  char wl2g_extern[16]; // [sp+90h] [bp+60h] BYREF
  char wl5g_extern[16]; // [sp+A0h] [bp+70h] BYREF
  _DWORD v37[65]; // [sp+B0h] [bp+80h] BYREF

  memset(wifi_chkHz, 0, 3);
  memset(wl2g_mib_radio, 0, sizeof(wl2g_mib_radio));
  memset(wl5g_mib_radio, 0, sizeof(wl5g_mib_radio));
  memset(wl2g_bss, 0, sizeof(wl2g_bss));
  memset(wl5g_bss, 0, sizeof(wl5g_bss));
  memset(wl2g_bss_guest, 0, sizeof(wl2g_bss_guest));
  memset(wl5g_bss_guest, 0, sizeof(wl5g_bss_guest));
  memset(wl2g_extern, 0, sizeof(wl2g_extern));
  memset(wl5g_extern, 0, sizeof(wl5g_extern));
  wifi_get_mib_radio(2, wl2g_mib_radio);
  wifi_get_mib_radio(5, wl5g_mib_radio);
  sprintf(wl2g_bss, "%s.0", wl2g_mib_radio);
  sprintf(wl5g_bss, "%s.0", wl5g_mib_radio);
  sprintf(wl2g_bss_guest, "%s.1", wl2g_mib_radio);
  sprintf(wl5g_bss_guest, "%s.1", wl5g_mib_radio);
  sprintf(wl2g_extern, "%s.x", wl2g_mib_radio);
  sprintf(wl5g_extern, "%s.x", wl5g_mib_radio);
  Object = cJSON_CreateObject();
  GetValue("wl.extra_chkHz", wifi_chkHz);
  if ( !wifi_chkHz[0] )
    strcpy(wifi_chkHz, "0");
  String = cJSON_CreateString(wifi_chkHz);
  cJSON_AddItemToObject(Object, "wifi_chkHz", String);
  v37[0] = 0;
  v37[1] = 0;
  GetValue("iptv.enable", v37);
  v5 = cJSON_CreateString((const char *)v37);
  cJSON_AddItemToObject(Object, "iptvEn", v5);
  memset(v37, 0, 0x100u);
  v23 = 0;
  v24 = 0;
  v25 = 0;
  v26 = 0;
  v27 = 0;
  v28 = 0;
  mibname = wifi_get_mibname(wl2g_bss_guest, "bss_enable", v37);
  GetValue(mibname, &v23);
  v7 = wifi_get_mibname(wl5g_bss_guest, "bss_enable", v37);
  GetValue(v7, &v25);
  if ( !strcmp((const char *)&v23, "1") || !strcmp((const char *)&v25, "1") )
    v8 = "1";
  else
    v8 = "0";
  strcpy((char *)&v27, v8);
  v9 = cJSON_CreateString((const char *)&v27);
  cJSON_AddItemToObject(Object, "guestEn", v9);
  memset(v37, 0, 0x100u);
  v23 = 0;
  v24 = 0;
  v25 = 0;
  v26 = 0;
  v27 = 0;
  v28 = 0;
  v10 = wifi_get_mibname(wl2g_bss, "bss_wps_enable", v37);
  GetValue(v10, &v23);
  v11 = wifi_get_mibname(wl5g_bss, "bss_wps_enable", v37);
  GetValue(v11, &v25);
  if ( !strcmp((const char *)&v23, "1") || !strcmp((const char *)&v25, "1") )
    v12 = "1";
  else
    v12 = "0";
  strcpy((char *)&v27, v12);
  v13 = cJSON_CreateString((const char *)&v27);
  cJSON_AddItemToObject(Object, "wpsEn", v13);
  memset(v37, 0, 0x10u);
  GetValue("sys.sched.wifi.enable", v37);
  v14 = cJSON_CreateString((const char *)v37);
  cJSON_AddItemToObject(Object, "wifiTimerEn", v14);
  LOWORD(v37[0]) = 0;
  wifi_status = get_wifi_status();
  sprintf((char *)v37, "%d", wifi_status);
  v16 = cJSON_CreateString((const char *)v37);
  cJSON_AddItemToObject(Object, "wl_enable", v16);
  v17 = atoi(wifi_chkHz) == 0;
  if ( v17 )
    v18 = wl2g_mib_radio;
  else
    v18 = wl5g_mib_radio;
  if ( v17 )
    v19 = wl2g_extern;
  else
    v19 = wl5g_extern;
  fromGetWirelessRepeat_wifi_chkHz((cJSON_0 *)Object, v18, v19);
  v20 = cJSON_Object_2String(Object);
  websTransfer(wp, v20);
}


/* Function: fromSetWirelessRepeat @ 0x3A724 */
void __fastcall fromSetWirelessRepeat(webs_t wp, char_t *path, char_t *query)
{
  _BOOL4 v3; // r8
  char_t *Var; // r4
  int mibname; // r0
  int v6; // r0
  bool v7; // zf
  int v8; // r9
  _BOOL4 v9; // r5
  int v10; // r0
  int v11; // r0
  int v12; // r0
  int v13; // r0
  char *v14; // r1
  const char *v15; // r0
  int v16; // r0
  int v17; // r0
  const char *v18; // r1
  int v19; // r0
  int v20; // r0
  int v21; // r0
  int v22; // r0
  char *v23; // r1
  int v24; // r0
  int v25; // r0
  int v26; // r0
  int v27; // r0
  char *nptr; // [sp+10h] [bp-20h]
  int v30; // [sp+24h] [bp-Ch] BYREF
  char ipv6_en[8]; // [sp+28h] [bp-8h] BYREF
  char wl2g_mib_radio[16]; // [sp+30h] [bp+0h] BYREF
  char wl5g_mib_radio[16]; // [sp+40h] [bp+10h] BYREF
  char wl2g_work_mode[16]; // [sp+50h] [bp+20h] BYREF
  char wl5g_work_mode[16]; // [sp+60h] [bp+30h] BYREF
  char mib_name[16]; // [sp+70h] [bp+40h] BYREF
  char before_wl_mode[16]; // [sp+80h] [bp+50h] BYREF
  char s[16]; // [sp+90h] [bp+60h] BYREF
  char v39[16]; // [sp+A0h] [bp+70h] BYREF
  char v40[16]; // [sp+B0h] [bp+80h] BYREF
  char v41[16]; // [sp+C0h] [bp+90h] BYREF
  char s1[16]; // [sp+D0h] [bp+A0h] BYREF
  char v43[16]; // [sp+E0h] [bp+B0h] BYREF
  char wl_extern[16]; // [sp+F0h] [bp+C0h] BYREF
  char v45[32]; // [sp+100h] [bp+D0h] BYREF
  char v46[32]; // [sp+120h] [bp+F0h] BYREF
  char tmp[256]; // [sp+140h] [bp+110h] BYREF
  _DWORD v48[129]; // [sp+240h] [bp+210h] BYREF

  memset(wl2g_mib_radio, 0, sizeof(wl2g_mib_radio));
  memset(wl5g_mib_radio, 0, sizeof(wl5g_mib_radio));
  memset(wl2g_work_mode, 0, sizeof(wl2g_work_mode));
  memset(wl5g_work_mode, 0, sizeof(wl5g_work_mode));
  v3 = 0;
  memset(tmp, 0, sizeof(tmp));
  memset(mib_name, 0, sizeof(mib_name));
  memset(before_wl_mode, 0, sizeof(before_wl_mode));
  memset(ipv6_en, 0, sizeof(ipv6_en));
  nptr = websGetVar(wp, "wifi_chkHz", "0");
  Var = websGetVar(wp, "wl_mode", "ap");
  wifi_get_mib_radio(2, wl2g_mib_radio);
  wifi_get_mib_radio(5, wl5g_mib_radio);
  mibname = wifi_get_mibname(wl2g_mib_radio, "workmode", mib_name);
  GetValue(mibname, wl2g_work_mode);
  v6 = wifi_get_mibname(wl5g_mib_radio, "workmode", mib_name);
  GetValue(v6, wl5g_work_mode);
  memset(s, 0, sizeof(s));
  memset(v39, 0, sizeof(v39));
  memset(v40, 0, sizeof(v40));
  memset(v41, 0, sizeof(v41));
  memset(s1, 0, sizeof(s1));
  memset(v43, 0, sizeof(v43));
  memset(wl_extern, 0, sizeof(wl_extern));
  memset(v48, 0, sizeof(v48));
  v48[128] = 256;
  v7 = nptr == 0;
  if ( nptr )
    v7 = Var == 0;
  v8 = v7;
  if ( v7 )
  {
    v9 = 1;
    goto finish;
  }
  sprintf(v40, "%s.1", wl2g_mib_radio);
  sprintf(v41, "%s.1", wl5g_mib_radio);
  sprintf(s, "%s.0", wl2g_mib_radio);
  sprintf(v39, "%s.0", wl5g_mib_radio);
  v10 = wifi_get_mibname(v40, "bss_enable", wl_extern);
  GetValue(v10, s1);
  v11 = wifi_get_mibname(v41, "bss_enable", wl_extern);
  GetValue(v11, v43);
  v30 = v8;
  if ( !strcmp("wisp", Var) )
    snprintf((char *)&v30, 4u, "%d", 5);
  else
    snprintf((char *)&v30, 4u, "%d", 1);
  SetValue("vpn.ser.pptpwanid", &v30);
  if ( !strcmp("ap", Var) )
  {
    memset(v46, 0, sizeof(v46));
    GetValue("sys.workmode", v46);
    GetValue("wl.extra_chkHz", v45);
    v12 = wifi_get_mibname(wl2g_mib_radio, "workmode", wl_extern);
    SetValue(v12, "ap");
    v13 = wifi_get_mibname(wl5g_mib_radio, "workmode", wl_extern);
    SetValue(v13, "ap");
    if ( !strcmp(v46, "ap") )
      v14 = "ap";
    else
      v14 = "router";
    v15 = "sys.workmode";
  }
  else
  {
    set_idx_to_mib(s, "bss_wps_enable", "0", v48);
    set_idx_to_mib(v39, "bss_wps_enable", "0", v48);
    SetValue("wl.guest.dhcps_enable", "0");
    if ( !strcmp(s1, "1") )
    {
      v16 = wifi_get_mibname(v40, "bss_enable", wl_extern);
      SetValue(v16, "0");
    }
    if ( !strcmp(v43, "1") )
    {
      v17 = wifi_get_mibname(v41, "bss_enable", wl_extern);
      SetValue(v17, "0");
    }
    SetValue("sys.workmode", Var);
    v14 = "1";
    v15 = "dhcps.en";
  }
  SetValue(v15, v14);
  if ( !strcmp(wl2g_work_mode, "ap") && !strcmp(wl5g_work_mode, "ap") && !strcmp(Var, "ap") )
  {
    v9 = 0;
    v3 = 0;
    goto finish;
  }
  if ( !strcmp(wl2g_work_mode, "wisp") || !strcmp(wl5g_work_mode, "wisp") )
  {
    v18 = "wisp";
  }
  else if ( !strcmp(wl2g_work_mode, "apclient") || !strcmp(wl5g_work_mode, "apclient") )
  {
    v18 = "apclient";
  }
  else
  {
    v18 = "ap";
  }
  strcpy(before_wl_mode, v18);
  v3 = strcmp(before_wl_mode, Var) != 0;
  SetValue("wl.extra_chkHz", nptr);
  v19 = atoi(nptr);
  if ( v19 )
  {
    if ( v19 == 1 )
    {
      memset(v43, 0, sizeof(v43));
      memset(wl_extern, 0, sizeof(wl_extern));
      memset(v45, 0, 0x10u);
      memset(v46, 0, 0x10u);
      memset(v48, 0, 0x10u);
      wifi_get_mib_radio(2, v46);
      wifi_get_mib_radio(5, v48);
      sprintf(wl_extern, "%s.x", (const char *)v48);
      v24 = wifi_get_mibname(v46, "workmode", v43);
      GetValue(v24, v45);
      if ( strcmp(Var, "ap") )
      {
        if ( strcmp(v45, "ap") )
        {
          v25 = wifi_get_mibname(v46, "workmode", v43);
          SetValue(v25, "ap");
        }
        v26 = wifi_get_mibname(v48, "workmode", v43);
        SetValue(v26, Var);
        v23 = "1";
LABEL_45:
        if ( wlSetExternParameter(wp, v23, wl_extern) == -1 )
        {
          v9 = 1;
          goto finish;
        }
      }
    }
  }
  else
  {
    memset(v43, 0, sizeof(v43));
    memset(wl_extern, 0, sizeof(wl_extern));
    memset(v45, 0, 0x10u);
    memset(v46, 0, 0x10u);
    memset(v48, 0, 0x10u);
    wifi_get_mib_radio(2, v46);
    wifi_get_mib_radio(5, v48);
    sprintf(wl_extern, "%s.x", v46);
    v20 = wifi_get_mibname(v48, "workmode", v43);
    GetValue(v20, v45);
    if ( strcmp(Var, "ap") )
    {
      if ( strcmp(v45, "ap") )
      {
        v21 = wifi_get_mibname(v48, "workmode", v43);
        SetValue(v21, "ap");
      }
      v22 = wifi_get_mibname(v46, "workmode", v43);
      SetValue(v22, Var);
      v23 = "0";
      goto LABEL_45;
    }
  }
  memset(v48, 0, 0x10u);
  SetValue("wans.flag", "1");
  memset(v48, 0, 0x10u);
  sprintf((char *)v48, "wan%d_err_check", 1);
  SetValue(v48, "0");
  memset(v48, 0, 0x10u);
  sprintf((char *)v48, "wan%d_isonln", 1);
  SetValue(v48, "0");
  memset(v48, 0, 0x10u);
  sprintf((char *)v48, "wan%d_check", 1);
  SetValue(v48, "0");
  v48[0] = 0;
  v48[1] = 0;
  if ( !strcmp(Var, "wisp") )
  {
    SetValue("wan1.connecttype", "0");
    SetValue("wan1.dhcp.dns.auto", "1");
    SetValue("wl.wisp.access_mode", "dhcp");
    GetValue("wan1.dynamicMTU", v48);
    SetValue("wl.wisp.mtu", v48);
    SetValue("wl.wisp.dns1", &byte_794DF);
    SetValue("wl.wisp.dns2", &byte_794DF);
    SetValue("wan1.ppoe.double.access", "0");
  }
  *(_DWORD *)wl_extern = 0;
  *(_DWORD *)v45 = 0;
  *(_DWORD *)v46 = 0;
  GetValue("vpn.cli.l2tpEnable", v45);
  GetValue("vpn.cli.pptpEnable", wl_extern);
  if ( !strcmp(Var, "ap") )
    snprintf(v46, 4u, "%d", 1);
  else
    snprintf(v46, 4u, "%d", 5);
  if ( !strcmp("1", wl_extern) )
    SetValue("vpn.cli.pptpwanid", v46);
  if ( !strcmp("1", v45) )
    SetValue("vpn.cli.l2tpwanid", v46);
  memset(v48, 0, 0x10u);
  GetValue("sys.sched.wifi.enable", v48);
  if ( !strcmp((const char *)v48, "1") )
    SetValue("sys.sched.wifi.enable", "0");
  memset(v48, 0, 0x10u);
  GetValue("sys.powersleep.enable", v48);
  if ( !strcmp((const char *)v48, "1") )
    SetValue("sys.powersleep.enable", "0");
  if ( !strcmp(before_wl_mode, "apclient") || !strcmp(Var, "apclient") )
    SetValue("dhcps.en", "1");
  SetValue("iptv.enable", "0");
  SetValue("iptv.stb.enable", "0");
  SetValue("igmp.enable", "0");
  GetValue("ipv6.enable", ipv6_en);
  v27 = strcmp(ipv6_en, "1");
  if ( !v27 )
    v27 = SetValue("ipv6.enable", "0");
  v9 = CommitSyncCfm(v27) == 0;
finish:
  sprintf(tmp, "{\"errCode\":%d}", v9);
  websTransfer(wp, tmp);
  if ( !v9 && (v3 || strcmp(Var, "ap")) )
    systool_sys_handle(0);
}
