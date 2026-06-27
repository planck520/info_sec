/* =====================================================
 *  Path 41
 *  vuln_type = CWE-120
 *  sink_func = sprintf
 *  source_func = websGetVar
 *  Hops:
 *    - sprintf (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - form_fast_setting_wifi_set (arg=2, call_ea=0x2d838, func_ea=0x2d628, label=needs_check)
 *        call: sprintf(ssid_5g, "%s_5G", v6);
 *    - websGetVar (arg=ret, call_ea=0x2d6f8, func_ea=source, label=source)
 *        call: Var = websGetVar(wp, "ssid", &byte_794DF);
 * ===================================================== */


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
