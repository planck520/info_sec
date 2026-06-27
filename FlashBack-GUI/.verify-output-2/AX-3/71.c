/* =====================================================
 *  Path 71
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - fromGetWrlStatus (arg=1, call_ea=0x38ed0, func_ea=0x38294, label=certain)
 *        call: GetValue("sys.workmode", v61);
 *    - fromSetWirelessRepeat (arg=1, call_ea=0x3aba0, func_ea=0x3a724, label=needs_check)
 *        call: SetValue("sys.workmode", Var);
 *    - websGetVar (arg=ret, call_ea=0x3a818, func_ea=source, label=source)
 *        call: Var = websGetVar(wp, "wl_mode", "ap");
 * ===================================================== */


/* Function: fromGetWrlStatus @ 0x38294 */
// local variable allocation has failed, the output may be wrong!
void __fastcall fromGetWrlStatus(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Object; // r4
  cJSON *String; // r0
  int mibname; // r0
  int v6; // r0
  const char *v7; // r1
  int v8; // r0
  int v9; // r0
  int v10; // r0
  int v11; // r7
  const char *v12; // r0
  int Value; // r0
  int lan_ifname; // r0
  cJSON *v15; // r0
  int v16; // r0
  int v17; // r0
  const char *v18; // r1
  cJSON *v19; // r0
  int v20; // r0
  int v21; // r0
  cJSON *v22; // r2
  int v23; // r0
  int v24; // r0
  char *v25; // r1
  char *v26; // r2
  int v27; // r0
  int v28; // r0
  int v29; // r0
  int v30; // r0
  int v31; // r0
  int v32; // r0
  int v33; // r0
  int v34; // r0
  const char *v35; // r1
  const char *v36; // r1
  int v37; // r9
  cJSON *v38; // r0
  cJSON *v39; // r2
  cJSON *v40; // r0
  cJSON *v41; // r0
  cJSON *v42; // r0
  cJSON *v43; // r0
  cJSON *v44; // r0
  cJSON *v45; // r2
  char *v46; // r5
  char_t *wpa; // [sp+0h] [bp-4D0h]
  _DWORD v49[2]; // [sp+20h] [bp-4B0h] BYREF
  _DWORD v50[2]; // [sp+28h] [bp-4A8h] BYREF
  _DWORD v51[2]; // [sp+30h] [bp-4A0h] BYREF
  _DWORD v52[4]; // [sp+38h] [bp-498h] BYREF
  char_t fmt[16]; // [sp+48h] [bp-488h] BYREF
  _DWORD v54[4]; // [sp+58h] [bp-478h] BYREF
  _DWORD v55[4]; // [sp+68h] [bp-468h] BYREF
  _DWORD v56[4]; // [sp+78h] [bp-458h] BYREF
  char wifi_band[32]; // [sp+88h] [bp-448h] OVERLAPPED BYREF
  char mib_name[256]; // [sp+A8h] [bp-428h] BYREF
  _DWORD s[64]; // [sp+1A8h] [bp-328h] BYREF
  _DWORD v60[64]; // [sp+2A8h] [bp-228h] BYREF
  char v61[296]; // [sp+3A8h] [bp-128h] BYREF

  memset(mib_name, 0, sizeof(mib_name));
  Object = cJSON_CreateObject();
  memset(v61, 0, 0x100u);
  GetValue("sys.sched.wifi.enable", v61);
  String = cJSON_CreateString(v61);
  cJSON_AddItemToObject(Object, "schedWifiEn", String);
  memset(s, 0, sizeof(s));
  memset(v60, 0, sizeof(v60));
  memset(v52, 0, sizeof(v52));
  memset(fmt, 0, sizeof(fmt));
  mibname = wifi_get_mibname("wlan0", "workmode", v60);
  GetValue(mibname, v52);
  v6 = wifi_get_mibname("wlan1", "workmode", v60);
  GetValue(v6, fmt);
  if ( !strcmp((const char *)v52, "ap") && !strcmp(fmt, "ap") )
  {
    v7 = "0";
LABEL_24:
    strcpy((char *)s, v7);
    goto LABEL_25;
  }
  strcpy((char *)s, "1");
  if ( strcmp((const char *)v52, "wisp") && strcmp(fmt, "wisp") )
  {
    if ( strcmp((const char *)v52, "apclient") && strcmp(fmt, "apclient") )
      goto LABEL_25;
    memset(wifi_band, 0, 0x19u);
    memset(v61, 0, 0x19u);
    Value = GetValue("lan.ip", wifi_band);
    lan_ifname = ifaddrs_get_lan_ifname(Value);
    if ( ifaddrs_get_ifip(lan_ifname, v61) < 0 || !strcmp(v61, wifi_band) )
      goto LABEL_25;
    v7 = "2";
    goto LABEL_24;
  }
  memset(v61, 0, 0x100u);
  memset(v54, 0, sizeof(v54));
  memset(v55, 0, sizeof(v55));
  memset(wifi_band, 0, sizeof(wifi_band));
  memset(v56, 0, sizeof(v56));
  v8 = wifi_get_mibname("wlan0", "workmode", v61);
  GetValue(v8, v54);
  v9 = wifi_get_mibname("wlan1", "workmode", v61);
  GetValue(v9, v55);
  v10 = wifi_get_mibname("wlan.x", "extern_access_mode", v61);
  GetValue(v10, v56);
  if ( !strcmp((const char *)v56, "static") )
  {
    v11 = 1;
  }
  else if ( !strcmp((const char *)v56, "dhcp") )
  {
    v11 = 0;
  }
  else if ( !strcmp((const char *)v56, "pppoe") )
  {
    v11 = 2;
  }
  else
  {
    v11 = 0;
  }
  if ( !strcmp((const char *)v54, "wisp") )
  {
    v12 = "wlan0.x";
  }
  else
  {
    if ( strcmp((const char *)v55, "wisp") )
      goto LABEL_25;
    v12 = "wlan1.x";
  }
  tpi_wifi_get_osifname(v12, wifi_band);
  if ( wifi_wisp_connect_check(wifi_band, v11) == 3 )
  {
    v7 = "2";
    goto LABEL_24;
  }
LABEL_25:
  v15 = cJSON_CreateString((const char *)s);
  cJSON_AddItemToObject(Object, "wispEn", v15);
  memset(v60, 0, sizeof(v60));
  memset(v61, 0, 0x100u);
  memset(wifi_band, 0, 0x10u);
  memset(s, 0, 0x10u);
  v16 = wifi_get_mibname("wlan0.0", "bss_wps_enable", v61);
  GetValue(v16, wifi_band);
  v17 = wifi_get_mibname("wlan1.0", "bss_wps_enable", v61);
  GetValue(v17, s);
  if ( !strcmp(wifi_band, "0") && !strcmp((const char *)s, "0") )
    v18 = "0";
  else
    v18 = "1";
  strcpy((char *)v60, v18);
  v19 = cJSON_CreateString((const char *)v60);
  cJSON_AddItemToObject(Object, "wpsEn", v19);
  memset(v61, 0, 0x100u);
  s[0] = 0;
  s[1] = 0;
  v60[0] = 0;
  v60[1] = 0;
  v20 = wifi_get_mibname("wlan0", "enable", v61);
  GetValue(v20, s);
  v21 = wifi_get_mibname("wlan1", "enable", v61);
  GetValue(v21, v60);
  if ( !strcmp((const char *)s, "1") || !strcmp((const char *)v60, "1") )
    v22 = cJSON_CreateString("1");
  else
    v22 = cJSON_CreateString("0");
  cJSON_AddItemToObject(Object, "namePwd", v22);
  memset(wifi_band, 0, 0x10u);
  v23 = wifi_get_mibname("wlan0", "band", mib_name);
  GetValue(v23, wifi_band);
  v24 = atoi(wifi_band);
  if ( v24 == 2 )
  {
    v25 = "wlan0";
    v26 = "wlan1";
LABEL_37:
    fromGetWrlStatus_wifi((cJSON_0 *)Object, v25, v26);
    goto LABEL_38;
  }
  if ( v24 == 5 )
  {
    v26 = "wlan0";
    v25 = "wlan1";
    goto LABEL_37;
  }
LABEL_38:
  memset(v61, 0, 0x100u);
  v49[1] = 0;
  v49[0] = 0;
  v50[0] = 0;
  v50[1] = 0;
  v51[0] = 0;
  v51[1] = 0;
  v52[0] = 0;
  v52[1] = 0;
  *(_DWORD *)fmt = 0;
  *(_DWORD *)&fmt[4] = 0;
  v54[0] = 0;
  v54[1] = 0;
  v55[0] = 0;
  v55[1] = 0;
  v56[0] = 0;
  v56[1] = 0;
  memset(s, 0, 0x20u);
  memset(v60, 0, 0x20u);
  v27 = wifi_get_mibname("wlan0", "enable", v61);
  GetValue(v27, v49);
  v28 = wifi_get_mibname("wlan1", "enable", v61);
  GetValue(v28, v50);
  v29 = wifi_get_mibname("wlan0", "web_ofdma", v61);
  GetValue(v29, fmt);
  v30 = wifi_get_mibname("wlan1", "web_ofdma", v61);
  GetValue(v30, v54);
  v31 = wifi_get_mibname("wlan0", "nettype", v61);
  GetValue(v31, s);
  v32 = wifi_get_mibname("wlan1", "nettype", v61);
  GetValue(v32, v60);
  v33 = wifi_get_mibname("wlan0.0", "bss_enable", v61);
  GetValue(v33, v55);
  v34 = wifi_get_mibname("wlan1.0", "bss_enable", v61);
  GetValue(v34, v56);
  if ( !strcmp((const char *)v49, "1") && !strcmp((const char *)v55, "1") )
    v35 = "1";
  else
    v35 = "0";
  strcpy((char *)v51, v35);
  if ( !strcmp((const char *)v50, "1") && !strcmp((const char *)v56, "1") )
    v36 = "1";
  else
    v36 = "0";
  strcpy((char *)v52, v36);
  v37 = strcmp((const char *)v51, "0");
  if ( !v37 && !strcmp((const char *)v52, "0") )
    goto LABEL_48;
  if ( strcmp((const char *)v51, "1") || strcmp((const char *)v52, "0") )
  {
    if ( v37 || strcmp((const char *)v52, "1") )
    {
      if ( strstr((const char *)s, "ax") )
      {
        if ( strstr((const char *)v60, "ax") )
        {
          v44 = cJSON_CreateString("1");
          cJSON_AddItemToObject(Object, "WebofdmaEn", v44);
          if ( strcmp(fmt, "0") || strcmp((const char *)v54, "0") )
            goto LABEL_74;
        }
        else
        {
          v42 = cJSON_CreateString("1");
          cJSON_AddItemToObject(Object, "WebofdmaEn", v42);
          if ( !strcmp(fmt, "1") )
            goto LABEL_74;
        }
      }
      else
      {
        if ( !strstr((const char *)v60, "ax") )
          goto LABEL_48;
        v43 = cJSON_CreateString("1");
        cJSON_AddItemToObject(Object, "WebofdmaEn", v43);
        if ( !strcmp((const char *)v54, "1") )
          goto LABEL_74;
      }
    }
    else
    {
      if ( !strstr((const char *)v60, "ax") )
        goto LABEL_48;
      v41 = cJSON_CreateString("1");
      cJSON_AddItemToObject(Object, "WebofdmaEn", v41);
      if ( !strcmp((const char *)v54, "1") )
        goto LABEL_74;
    }
LABEL_73:
    v39 = cJSON_CreateString("0");
    goto LABEL_75;
  }
  if ( !strstr((const char *)s, "ax") )
  {
LABEL_48:
    v38 = cJSON_CreateString("0");
    cJSON_AddItemToObject(Object, "WebofdmaEn", v38);
    v39 = cJSON_CreateString("0");
    goto LABEL_75;
  }
  v40 = cJSON_CreateString("1");
  cJSON_AddItemToObject(Object, "WebofdmaEn", v40);
  if ( strcmp(fmt, "1") )
    goto LABEL_73;
LABEL_74:
  v39 = cJSON_CreateString("1");
LABEL_75:
  cJSON_AddItemToObject(Object, "ofdmaEn", v39);
  memset(v61, 0, 0x100u);
  GetValue("sys.workmode", v61);
  if ( !strcmp(v61, "ap") )
    v45 = cJSON_CreateString("1");
  else
    v45 = cJSON_CreateString("0");
  cJSON_AddItemToObject(Object, "apMode", v45);
  v46 = cJSON_Print(Object);
  cJSON_Delete(Object);
  websWrite(wp, fmt);
  websWrite(wp, wpa);
  free(v46);
  websDone(wp, 200);
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
