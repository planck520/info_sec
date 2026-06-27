/* =====================================================
 *  Path 67
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - fromGetWifiGusetBasic (arg=1, call_ea=0x3f68c, func_ea=0x3f450, label=certain)
 *        call: GetValue("wl.guest.down_speed", mib_value);
 *    - fromSetWifiGusetBasic (arg=1, call_ea=0x3f134, func_ea=0x3e9c8, label=certain)
 *        call: SetValue("wl.guest.down_speed", Var);
 *    - websGetVar (arg=ret, call_ea=0x3eb0c, func_ea=source, label=source)
 *        call: Var = websGetVar(wp, "shareSpeed", "0");
 * ===================================================== */


/* Function: fromGetWifiGusetBasic @ 0x3F450 */
void __fastcall fromGetWifiGusetBasic(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Object; // r4
  int wifi_status; // r0
  cJSON *String; // r0
  int v7; // r0
  const char *wifi_workmode; // r0
  cJSON *v9; // r0
  int mibname; // r0
  int v11; // r0
  int v12; // r0
  cJSON *v13; // r0
  cJSON *v14; // r0
  char *v15; // r5
  char *wl_ifname; // [sp+0h] [bp-B8h]
  char_t *wl_ifnamea; // [sp+0h] [bp-B8h]
  char value[4]; // [sp+Ch] [bp-ACh] BYREF
  char wl_mode[16]; // [sp+10h] [bp-A8h] BYREF
  char mib_name[16]; // [sp+20h] [bp-98h] BYREF
  char mib_value[32]; // [sp+30h] [bp-88h] BYREF
  char effect_time_string[32]; // [sp+50h] [bp-68h] BYREF
  char wifi_band[32]; // [sp+70h] [bp-48h] BYREF

  memset(wl_mode, 0, sizeof(wl_mode));
  memset(mib_name, 0, sizeof(mib_name));
  memset(mib_value, 0, sizeof(mib_value));
  memset(effect_time_string, 0, sizeof(effect_time_string));
  memset(wifi_band, 0, sizeof(wifi_band));
  Object = cJSON_CreateObject();
  *(_WORD *)value = 0;
  wifi_status = get_wifi_status();
  sprintf(value, "%d", wifi_status);
  String = cJSON_CreateString(value);
  cJSON_AddItemToObject(Object, "wl_en", String);
  wifi_workmode = (const char *)get_wifi_workmode(v7);
  strcpy(wl_mode, wifi_workmode);
  v9 = cJSON_CreateString(wl_mode);
  cJSON_AddItemToObject(Object, "wl_mode", v9);
  mibname = wifi_get_mibname("wlan0", "band", mib_name);
  GetValue(mibname, wifi_band);
  v11 = atoi(wifi_band);
  if ( v11 == 2 )
  {
    fromGetWifiGusetBasic_2G((cJSON_0 *)Object, "wlan0", "wlan1", "wlan0.1", "wlan0.0");
    fromGetWifiGusetBasic_5G((cJSON_0 *)Object, "wlan0", "wlan1", "wlan1.1", "wlan1.0");
  }
  else if ( v11 == 5 )
  {
    fromGetWifiGusetBasic_2G((cJSON_0 *)Object, "wlan1", "wlan0", "wlan1.1", "wlan1.0");
    fromGetWifiGusetBasic_5G((cJSON_0 *)Object, "wlan1", "wlan0", "wlan0.1", "wlan0.0");
  }
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("wl.guest.effective_time", mib_value);
  v12 = atoi(mib_value);
  snprintf(effect_time_string, 0x20u, "%d", v12 / 3600);
  v13 = cJSON_CreateString(effect_time_string);
  cJSON_AddItemToObject(Object, "effectiveTime", v13);
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("wl.guest.down_speed", mib_value);
  if ( !mib_value[0] )
    strcpy(mib_value, "0");
  v14 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "shareSpeed", v14);
  v15 = cJSON_Print(Object);
  cJSON_Delete(Object);
  websWrite(wp, wl_ifname);
  websWrite(wp, wl_ifnamea);
  free(v15);
  websDone(wp, 200);
}


/* Function: fromSetWifiGusetBasic @ 0x3E9C8 */
void __fastcall fromSetWifiGusetBasic(webs_t wp, char_t *path, char_t *query)
{
  int mibname; // r0
  int v5; // r0
  int v6; // r0
  int v7; // r0
  int v8; // r0
  int v9; // r0
  int v10; // r0
  int v11; // r0
  const char *v12; // r1
  _BOOL4 v13; // r7
  int v14; // r2
  int v15; // r0
  int v16; // r0
  cgi_msg v17; // r5
  char *v18; // r2
  char *v19; // r1
  char_t *v20; // r9
  int v21; // r0
  int v22; // r0
  int v23; // r6
  int v24; // r8
  int v25; // r0
  int v26; // r0
  char_t *v27; // r0
  _BOOL4 v28; // r9
  int v29; // r0
  int v30; // r0
  char *v31; // r1
  char *Var; // [sp+8h] [bp-7CCh]
  char *nptr; // [sp+Ch] [bp-7C8h]
  char *s1; // [sp+10h] [bp-7C4h]
  char *v35; // [sp+14h] [bp-7C0h]
  char *v36; // [sp+18h] [bp-7BCh]
  char *v37; // [sp+1Ch] [bp-7B8h]
  char wlan0_work_mode[16]; // [sp+3Ch] [bp-798h] BYREF
  char wlan1_work_mode[16]; // [sp+4Ch] [bp-788h] BYREF
  char bandwidth_listnum[16]; // [sp+5Ch] [bp-778h] BYREF
  char shared_up_speed[16]; // [sp+6Ch] [bp-768h] BYREF
  _BYTE s[16]; // [sp+7Ch] [bp-758h] BYREF
  char v43[32]; // [sp+8Ch] [bp-748h] BYREF
  char tmp[256]; // [sp+ACh] [bp-728h] BYREF
  char mib_name[256]; // [sp+1ACh] [bp-628h] BYREF
  char v46[256]; // [sp+2ACh] [bp-528h] BYREF
  char v47[256]; // [sp+3ACh] [bp-428h] BYREF
  char v48[256]; // [sp+4ACh] [bp-328h] BYREF
  char v49[256]; // [sp+5ACh] [bp-228h] BYREF
  char v50[296]; // [sp+6ACh] [bp-128h] BYREF

  memset(wlan0_work_mode, 0, sizeof(wlan0_work_mode));
  memset(wlan1_work_mode, 0, sizeof(wlan1_work_mode));
  memset(bandwidth_listnum, 0, sizeof(bandwidth_listnum));
  memset(tmp, 0, sizeof(tmp));
  memset(shared_up_speed, 0, sizeof(shared_up_speed));
  memset(mib_name, 0, sizeof(mib_name));
  tdSyslog(1, "WiFi Guest Set");
  mibname = wifi_get_mibname("wlan0", "workmode", mib_name);
  GetValue(mibname, wlan0_work_mode);
  v5 = wifi_get_mibname("wlan1", "workmode", mib_name);
  GetValue(v5, wlan1_work_mode);
  GetValue("bandwidth.mode.listnum", bandwidth_listnum);
  Var = websGetVar(wp, "shareSpeed", "0");
  strcpy(shared_up_speed, Var);
  memset(v46, 0, sizeof(v46));
  memset(v47, 0, sizeof(v47));
  memset(v48, 0, sizeof(v48));
  memset(v49, 0, sizeof(v49));
  memset(v50, 0, 0x100u);
  memset(s, 0, sizeof(s));
  memset(v43, 0, sizeof(v43));
  s1 = websGetVar(wp, "guestSsid", &byte_794DF);
  v35 = websGetVar(wp, "guestWrlPwd", &byte_794DF);
  v36 = websGetVar(wp, "guestSsid_5g", &byte_794DF);
  v37 = websGetVar(wp, "guestWrlPwd_5g", &byte_794DF);
  v6 = wifi_get_mibname("wlan0.1", "bss_ssid", v50);
  GetValue(v6, v46);
  v7 = wifi_get_mibname("wlan0.1", "bss_wpapsk_key", v50);
  GetValue(v7, v47);
  v8 = wifi_get_mibname("wlan1.1", "bss_ssid", v50);
  GetValue(v8, v48);
  v9 = wifi_get_mibname("wlan1.1", "bss_wpapsk_key", v50);
  GetValue(v9, v49);
  v10 = wifi_get_mibname("wlan0", "band", s);
  GetValue(v10, v43);
  v11 = atoi(v43);
  if ( v11 == 2 )
  {
    if ( !strcmp(s1, v46) && !strcmp(v35, v47) && !strcmp(v36, v48) )
    {
      v12 = v49;
LABEL_13:
      v13 = strcmp(v37, v12) != 0;
      goto LABEL_15;
    }
    goto LABEL_14;
  }
  if ( v11 == 5 )
  {
    if ( !strcmp(s1, v48) && !strcmp(v35, v49) && !strcmp(v36, v46) )
    {
      v12 = v47;
      goto LABEL_13;
    }
LABEL_14:
    v13 = 1;
    goto LABEL_15;
  }
  v13 = 0;
LABEL_15:
  if ( strcmp(wlan0_work_mode, "ap") || strcmp(wlan1_work_mode, "ap") )
    goto LABEL_16;
  memset(v49, 0, 0x10u);
  memset(v50, 0, 0x20u);
  v15 = wifi_get_mibname("wlan0", "band", v49);
  GetValue(v15, v50);
  v16 = atoi(v50);
  if ( v16 == 2 )
  {
    v17 = setWifiGusetBasic_2G(wp, "wlan0", "wlan0.1");
    v18 = "wlan1.1";
    v19 = "wlan1";
    goto LABEL_22;
  }
  if ( v16 == 5 )
  {
    v17 = setWifiGusetBasic_2G(wp, "wlan1", "wlan1.1");
    v19 = "wlan0";
    v18 = "wlan0.1";
LABEL_22:
    if ( !(v17 | setWifiGusetBasic_5G(wp, v19, v18)) )
      goto LABEL_23;
LABEL_16:
    v14 = 1;
    goto finish;
  }
LABEL_23:
  memset(v47, 0, 0x10u);
  memset(v48, 0, 0x10u);
  memset(v49, 0, sizeof(v49));
  memset(v50, 0, 0x100u);
  GetValue("wl.guest.dhcps_enable", v47);
  GetValue("bandwidth.mode.listnum", v48);
  v20 = websGetVar(wp, "guestEn", "1");
  nptr = websGetVar(wp, "guestEn_5g", "1");
  if ( !strcmp(v20, "1") || !strcmp(nptr, "1") )
  {
    v21 = wifi_get_mibname("wlan0.1", "bss_brid", v49);
    SetValue(v21, "1");
    v22 = wifi_get_mibname("wlan1.1", "bss_brid", v49);
    SetValue(v22, "1");
    v23 = strcmp(v47, "0");
    if ( v23 )
    {
      v23 = 0;
      v24 = 0;
      goto LABEL_35;
    }
    SetValue("wl.guest.dhcps_enable", "1");
  }
  else
  {
    v25 = wifi_get_mibname("wlan0.1", "bss_brid", v49);
    SetValue(v25, "0");
    v26 = wifi_get_mibname("wlan1.1", "bss_brid", v49);
    SetValue(v26, "0");
    if ( strcmp(v47, "1") )
    {
      v23 = 1;
      v24 = 0;
      goto LABEL_35;
    }
    SetValue("wl.guest.dhcps_enable", "0");
    if ( !v48[0] || !strcmp(v48, "1") )
      SetValue("adv.qos.en", "0");
    unSetQosOldMiblist();
    v23 = 0;
    snprintf(v50, 0x100u, "op=%d", 6);
    send_msg_to_netctrl(15, v50);
  }
  v24 = 1;
LABEL_35:
  memset(v50, 0, 0x100u);
  v27 = websGetVar(wp, "effectiveTime", "4");
  v28 = (_BOOL4)v27;
  if ( v27 )
  {
    v29 = atoi(v27);
    snprintf(v50, 0x100u, "%d", 3600 * v29);
    printf("[ %s:%d ] effect_time == %s\n", "fromSetWifiGusetBasic_effect_time", 241, v50);
    SetValue("wl.guest.effective_time", v50);
    v28 = atoi((const char *)v28) != 0;
  }
  SetValue("wl.guest.down_speed", Var);
  set_wl_guest_qos_list(shared_up_speed, Var);
  if ( !CommitCfm(v30) )
    goto LABEL_16;
  if ( !v23 )
  {
    memset(v49, 0, 0x10u);
    memset(v50, 0, 0x100u);
    GetValue("wl.guest.dhcps_enable", v49);
    if ( v28 && !strncmp(v49, "1", 0x10u) )
      send_msg_to_netctrl(65, "string_info=wl_guest");
    if ( !strncmp(v49, "1", 0x10u) )
    {
      if ( atoi(Var) || bandwidth_listnum[0] && strcmp(bandwidth_listnum, "1") )
        v31 = "1";
      else
        v31 = "0";
      SetValue("adv.qos.en", v31);
      unSetQosOldMiblist();
      snprintf(v50, 0x100u, "op=%d", 6);
      send_msg_to_netctrl(15, v50);
    }
    if ( v24 | v13 )
    {
      memset(v50, 0, 0x100u);
      sprintf(v50, "op=%d,wl_rate=%d,index=1", 3, 7);
      send_msg_to_netctrl(19, v50);
    }
    memset(v50, 0, 0x100u);
    if ( v24 == 1 )
    {
      unSetQosOldMiblist();
      snprintf(v50, 0x100u, "op=%d", 6);
      send_msg_to_netctrl(15, v50);
      printf("----%s----%d-----\n", "fromSetWifiGusetBasic_guest_change", 321);
      snprintf(v50, 0x100u, "op=%d", 10);
      send_msg_to_netctrl(19, v50);
    }
  }
  v14 = 0;
finish:
  sprintf(tmp, "{\"errCode\":%d}", v14);
  websTransfer(wp, tmp);
}
