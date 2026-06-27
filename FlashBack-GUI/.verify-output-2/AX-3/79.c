/* =====================================================
 *  Path 79
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formGetAdvanceStatus (arg=1, call_ea=0x5ebc8, func_ea=0x5e8c0, label=certain)
 *        call: GetValue("sys.userpass", userpass);
 *    - form_fast_setting_wifi_set (arg=1, call_ea=0x2dbd0, func_ea=0x2d628, label=certain)
 *        call: SetValue("sys.userpass", v20);
 *    - websGetVar (arg=ret, call_ea=0x2dbbc, func_ea=source, label=source)
 *        call: v20 = websGetVar(wp, "loginPwd", &byte_794DF);
 * ===================================================== */


/* Function: formGetAdvanceStatus @ 0x5E8C0 */
void __fastcall formGetAdvanceStatus(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Object; // r4
  const char *v5; // r1
  int mibname; // r0
  int v7; // r0
  const char *v8; // r1
  cJSON *String; // r2
  cJSON *v10; // r0
  cJSON *v11; // r0
  cJSON *v12; // r0
  cJSON *v13; // r0
  cJSON *v14; // r0
  cJSON *v15; // r0
  cJSON *v16; // r0
  cJSON *v17; // r0
  cJSON *v18; // r0
  cJSON *v19; // r0
  cJSON *v20; // r0
  const char *v21; // r0
  cJSON *v22; // r0
  const char *v23; // r0
  cJSON *v24; // r0
  const char *v25; // r0
  cJSON *v26; // r0
  const char *v27; // r0
  cJSON *v28; // r0
  cJSON *v29; // r0
  char *v30; // r5
  char_t *v31; // [sp+0h] [bp-2A0h]
  char_t *v32; // [sp+0h] [bp-2A0h]
  char netControl[8]; // [sp+20h] [bp-280h] BYREF
  char led[8]; // [sp+28h] [bp-278h] BYREF
  char cloud[8]; // [sp+30h] [bp-270h] BYREF
  char sleepMode[8]; // [sp+38h] [bp-268h] BYREF
  char remoteWeb[8]; // [sp+40h] [bp-260h] BYREF
  char ddns[8]; // [sp+48h] [bp-258h] BYREF
  char upnp[8]; // [sp+50h] [bp-250h] BYREF
  char iptv[8]; // [sp+58h] [bp-248h] BYREF
  char staticroute[8]; // [sp+60h] [bp-240h] BYREF
  char virtarlser[8]; // [sp+68h] [bp-238h] BYREF
  char dmz_en[8]; // [sp+70h] [bp-230h] BYREF
  char wl24g_work_mode[24]; // [sp+78h] [bp-228h] BYREF
  char wl5g_work_mode[24]; // [sp+90h] [bp-210h] BYREF
  char wl_mode[24]; // [sp+A8h] [bp-1F8h] BYREF
  char mib_value[32]; // [sp+C0h] [bp-1E0h] BYREF
  char userpass[64]; // [sp+E0h] [bp-1C0h] BYREF
  char tr69_enable[128]; // [sp+120h] [bp-180h] BYREF
  char mac_filter_mode[256]; // [sp+1A0h] [bp-100h] BYREF
  char mib_name[256]; // [sp+2A0h] [bp+0h] BYREF

  memset(netControl, 0, sizeof(netControl));
  memset(led, 0, sizeof(led));
  memset(cloud, 0, sizeof(cloud));
  memset(sleepMode, 0, sizeof(sleepMode));
  memset(remoteWeb, 0, sizeof(remoteWeb));
  memset(ddns, 0, sizeof(ddns));
  memset(upnp, 0, sizeof(upnp));
  memset(iptv, 0, sizeof(iptv));
  memset(staticroute, 0, sizeof(staticroute));
  memset(virtarlser, 0, sizeof(virtarlser));
  memset(mib_value, 0, sizeof(mib_value));
  memset(wl24g_work_mode, 0, sizeof(wl24g_work_mode));
  memset(wl5g_work_mode, 0, sizeof(wl5g_work_mode));
  memset(wl_mode, 0, sizeof(wl_mode));
  memset(userpass, 0, sizeof(userpass));
  memset(dmz_en, 0, sizeof(dmz_en));
  memset(mac_filter_mode, 0, sizeof(mac_filter_mode));
  memset(mib_name, 0, sizeof(mib_name));
  memset(tr69_enable, 0, sizeof(tr69_enable));
  Object = cJSON_CreateObject();
  GetValue("adv.qos.en", netControl);
  GetValue("ucloud.en", cloud);
  GetValue("sys.powersleep.enable", sleepMode);
  GetValue("wans.wanweben", remoteWeb);
  GetValue("adv.ddns1.en", ddns);
  GetValue("adv.upnp.en", upnp);
  GetValue("iptv.enable", iptv);
  GetValue("sys.sched.led.type", mib_value);
  GetValue("adv.staticroute.listnum", staticroute);
  GetValue("adv.virtualser.listnum", virtarlser);
  if ( !strncmp(mib_value, "open", 4u) )
    v5 = "0";
  else
    v5 = "1";
  strcpy(led, v5);
  mibname = wifi_get_mibname("wlan0", "workmode", mib_name);
  GetValue(mibname, wl24g_work_mode);
  v7 = wifi_get_mibname("wlan1", "workmode", mib_name);
  GetValue(v7, wl5g_work_mode);
  if ( !strcmp(wl24g_work_mode, "wisp") || !strcmp(wl5g_work_mode, "wisp") )
  {
    v8 = "wisp";
  }
  else if ( !strcmp(wl24g_work_mode, "apclient") || !strcmp(wl5g_work_mode, "apclient") )
  {
    v8 = "apclient";
  }
  else
  {
    v8 = "ap";
  }
  strcpy(wl_mode, v8);
  GetValue("wan1.dmzen", dmz_en);
  GetValue("sys.userpass", userpass);
  if ( userpass[0] )
    String = cJSON_CreateString("false");
  else
    String = cJSON_CreateString("true");
  cJSON_AddItemToObject(Object, "nopwd", String);
  GetValue("cwmp.manage.enable", tr69_enable);
  v10 = cJSON_CreateString(tr69_enable);
  cJSON_AddItemToObject(Object, "tr069", v10);
  v11 = cJSON_CreateString(netControl);
  cJSON_AddItemToObject(Object, "netControl", v11);
  v12 = cJSON_CreateString(led);
  cJSON_AddItemToObject(Object, "led", v12);
  v13 = cJSON_CreateString(cloud);
  cJSON_AddItemToObject(Object, "cloud", v13);
  v14 = cJSON_CreateString(sleepMode);
  cJSON_AddItemToObject(Object, "sleepMode", v14);
  v15 = cJSON_CreateString(remoteWeb);
  cJSON_AddItemToObject(Object, "remoteWeb", v15);
  v16 = cJSON_CreateString(ddns);
  cJSON_AddItemToObject(Object, "ddns", v16);
  v17 = cJSON_CreateString(upnp);
  cJSON_AddItemToObject(Object, "upnp", v17);
  v18 = cJSON_CreateString(iptv);
  cJSON_AddItemToObject(Object, "iptv", v18);
  v19 = cJSON_CreateString(wl_mode);
  cJSON_AddItemToObject(Object, "wl_mode", v19);
  v20 = cJSON_CreateString(dmz_en);
  cJSON_AddItemToObject(Object, "dmz", v20);
  if ( GetParentCtrlStatus() )
    v21 = "1";
  else
    v21 = "0";
  v22 = cJSON_CreateString(v21);
  cJSON_AddItemToObject(Object, "parentControl", v22);
  if ( firewall_status() )
    v23 = "1";
  else
    v23 = "0";
  v24 = cJSON_CreateString(v23);
  cJSON_AddItemToObject(Object, "firewall", v24);
  if ( atoi(staticroute) )
    v25 = "1";
  else
    v25 = "0";
  v26 = cJSON_CreateString(v25);
  cJSON_AddItemToObject(Object, "staticRoute", v26);
  if ( atoi(virtarlser) )
    v27 = "1";
  else
    v27 = "0";
  v28 = cJSON_CreateString(v27);
  cJSON_AddItemToObject(Object, "virtualServer", v28);
  get_macfilter_mode(mac_filter_mode);
  v29 = cJSON_CreateString(mac_filter_mode);
  cJSON_AddItemToObject(Object, "macFilterType", v29);
  v30 = cJSON_Print(Object);
  cJSON_Delete(Object);
  websWrite(wp, v31);
  websWrite(wp, v32);
  free(v30);
  websDone(wp, 200);
}


/* Function: form_fast_setting_wifi_set @ 0x2D628 */
// local variable allocation has failed, the output may be wrong!
void __fastcall form_fast_setting_wifi_set(webs_t wp, char_t *path, char_t *query)
{
  int v4; // r7
  char_t *Var; // r0
  const char *v6; // r8
  int v7; // r0
  int v8; // r2
  int mibname; // r0
  int v10; // r0
  const char *v11; // r0
  char_t *v12; // r11
  const char *v13; // r2
  const char *v14; // r1
  int v15; // r1
  int v16; // r2
  char_t *v17; // r0
  const char *v18; // r8
  char *v19; // r2
  char_t *v20; // r9
  int i; // r9
  char_t *v22; // r0
  char_t *v23; // r7
  login_ip_time *v24; // r7
  int v25; // r2
  int v26; // r7
  cJSON *Object; // r4
  cJSON *Number; // r0
  cJSON *String; // r0
  char *v30; // r0
  char quickset_flag[4]; // [sp+1Ch] [bp-14h] BYREF
  int v32; // [sp+20h] [bp-10h] BYREF
  int v33; // [sp+24h] [bp-Ch] BYREF
  char unity_enable[8]; // [sp+28h] [bp-8h] BYREF
  char wifi_band[16]; // [sp+30h] [bp+0h] BYREF
  char_t ssid_24g[64]; // [sp+40h] [bp+10h] BYREF
  char_t ssid_5g[64]; // [sp+80h] [bp+50h] BYREF
  char mib_name[256]; // [sp+C0h] [bp+90h] BYREF
  char param_str[256]; // [sp+1C0h] [bp+190h] BYREF
  WIFI_BUF wl_buf; // [sp+2C0h] [bp+290h] BYREF
  _BYTE par[516]; // [sp+4C4h] [bp+494h] OVERLAPPED BYREF

  v4 = 0;
  memset(ssid_24g, 0, sizeof(ssid_24g));
  memset(ssid_5g, 0, sizeof(ssid_5g));
  *(_DWORD *)quickset_flag = 0;
  memset(unity_enable, 0, sizeof(unity_enable));
  memset(wifi_band, 0, sizeof(wifi_band));
  memset(mib_name, 0, sizeof(mib_name));
  memset(param_str, 0, sizeof(param_str));
  memset(&wl_buf, 0, sizeof(wl_buf));
  wl_buf.max_length = 256;
  Var = websGetVar(wp, "ssid", &byte_794DF);
  if ( !*Var )
  {
    printf("%s [%d] no ssid set, just return.\n", "form_fast_setting_wifi_set", 865);
    websRedirect(wp, "login.html");
    return;
  }
  v6 = Var;
  snprintf(ssid_24g, 0x40u, "%s", Var);
  GetValue("wlan0_ssid5g_prio", unity_enable);
  if ( atoi(unity_enable) == 1 )
  {
    snprintf(ssid_5g, 0x40u, "%s", v6);
  }
  else
  {
    memset(par, 0, 0x40u);
    strcpy(par, v6);
    while ( 1 )
    {
      v7 = strcasestr(par, "2.4G");
      if ( !v7 )
        break;
      v8 = *(unsigned __int8 *)(v7 + 3);
      ++v4;
      *(_BYTE *)v7 = 53;
      if ( v8 == 71 || v8 == 103 )
        *(_BYTE *)(v7 + 1) = v8;
      *(_BYTE *)(v7 + 2) = 0;
      strcat(par, (const char *)(v7 + 4));
    }
    if ( v4 )
      strcpy(ssid_5g, par);
    else
      sprintf(ssid_5g, "%s_5G", v6);
  }
  mibname = wifi_get_mibname("wlan0", "band", mib_name);
  GetValue(mibname, wifi_band);
  v10 = atoi(wifi_band);
  if ( v10 == 2 )
  {
    set_idx_to_mib("wlan0.0", "bss_ssid", ssid_24g, &wl_buf);
    v11 = "wlan1.0";
  }
  else
  {
    if ( v10 != 5 )
      goto LABEL_19;
    set_idx_to_mib("wlan1.0", "bss_ssid", ssid_24g, &wl_buf);
    v11 = "wlan0.0";
  }
  set_idx_to_mib(v11, "bss_ssid", ssid_5g, &wl_buf);
LABEL_19:
  v12 = websGetVar(wp, "wrlPassword", &byte_794DF);
  if ( *v12 )
  {
    set_idx_to_mib("wlan1.0", "bss_security", "wpapsk", &wl_buf);
    set_idx_to_mib("wlan0.0", "bss_security", "wpapsk", &wl_buf);
    set_idx_to_mib("wlan1.0", "bss_wpapsk_type", "psk+psk2", &wl_buf);
    set_idx_to_mib("wlan0.0", "bss_wpapsk_type", "psk+psk2", &wl_buf);
    set_idx_to_mib("wlan1.0", "bss_wpapsk_crypto", "aes", &wl_buf);
    set_idx_to_mib("wlan0.0", "bss_wpapsk_crypto", "aes", &wl_buf);
    set_idx_to_mib("wlan1.0", "bss_wpapsk_key", v12, &wl_buf);
    v13 = v12;
    v14 = "bss_wpapsk_key";
  }
  else
  {
    set_idx_to_mib("wlan1.0", "bss_security", "none", &wl_buf);
    v13 = "none";
    v14 = "bss_security";
  }
  set_idx_to_mib("wlan0.0", v14, v13, &wl_buf);
  SetValue("sys.quickset.cfg", "0");
  if ( proc_check_app("pppoe-server", v15, v16) )
  {
    snprintf(param_str, 0x100u, "op=%d", 2);
    send_msg_to_netctrl(66, param_str);
  }
  GetValue("sys.quickset.cfg", quickset_flag);
  printf("[%s]{%d}:sys.quickset.cfg = %s\n", "form_fast_setting_wifi_set", 921, quickset_flag);
  memset(par, 0, sizeof(par));
  *(_DWORD *)&par[512] = 256;
  v17 = websGetVar(wp, "power", &byte_794DF);
  v18 = v17;
  if ( !*v17 )
    goto LABEL_30;
  if ( !strcmp(v17, "low") )
  {
    v19 = "low";
LABEL_29:
    set_idx_to_mib("wlan1", "power", v19, par);
    goto LABEL_30;
  }
  if ( !strcmp(v18, "high") )
  {
    v19 = "high";
    goto LABEL_29;
  }
LABEL_30:
  printf("[%s]{%d}:set power = %s\n", "form_fast_setting_wifi_power", 708, v18);
  memset(par, 0, 0x100u);
  v20 = websGetVar(wp, "loginPwd", &byte_794DF);
  GetValue("sys.userpass", par);
  SetValue("sys.userpass", v20);
  printf("[%s]{%d}:set userpass = %s\n", "form_fast_setting_loginpwd", 722, v20);
  getwebuserpwd(1);
  if ( strcmp(par, v20) )
  {
    for ( i = 0; i != 3; ++i )
    {
      v24 = &loginUserInfo[i];
      if ( !strcmp(loginUserInfo[i].ip, wp->ipaddr) )
      {
        memset(v24, 0, 0x28u);
        v24->time = 0;
      }
    }
  }
  v32 = 0;
  v33 = 0;
  v22 = websGetVar(wp, "timeZone", &byte_794DF);
  v23 = v22;
  if ( v22 )
  {
    if ( *v22 )
    {
      v22 = (char_t *)_isoc99_sscanf(v22 + 1, "%[^:]:%s", par);
      if ( v22 == (char_t *)2 )
      {
        if ( *v23 == 45 )
          v25 = 12 - atoi(par);
        else
          v25 = atoi(par) + 12;
        sprintf((char *)&v32, "%d", v25);
        strcpy((char *)&v33, &par[4]);
        SetValue("sys.timezone", &v32);
        SetValue("sys.timenextzone", &v33);
        v22 = (char_t *)printf(
                          "[%s]{%d}:set sys.timezone = %s\n",
                          "form_fast_setting_timezone",
                          773,
                          (const char *)&v32);
      }
    }
  }
  else
  {
    v22 = (char_t *)printf("[%s][%d]:get var error!!!\n", "form_fast_setting_timezone", 750);
  }
  if ( CommitCfm(v22) )
  {
    memset(par, 0, 0x10u);
    sprintf(par, "op=%d", 3);
    printf("[%s]{%d}:send to NETCTRL_MODULE_SNTP :%s\n", "form_fast_setting_wifi_set", 931, par);
    send_msg_to_netctrl(24, par);
    sprintf(par, "op=%d,wl_rate=%d", 3, 7);
    v26 = 0;
    printf("[%s]{%d}:send to NETCTRL_MODULE_WIFI :%s\n", "form_fast_setting_wifi_set", 935, par);
    send_msg_to_netctrl(19, par);
  }
  else
  {
    v26 = 1;
  }
  Object = cJSON_CreateObject();
  Number = cJSON_CreateNumber((double)v26);
  cJSON_AddItemToObject(Object, "errCode", Number);
  String = cJSON_CreateString(ssid_5g);
  cJSON_AddItemToObject(Object, "ssid_5g", String);
  v30 = cJSON_Object_2String(Object);
  websTransfer(wp, v30);
}
