/* =====================================================
 *  Path 68
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - getSchedWifi (arg=1, call_ea=0x3d2ec, func_ea=0x3d254, label=certain)
 *        call: GetValue("sys.sched.wifi.timeType", timeType);
 *    - setSchedWifi (arg=1, call_ea=0x3d764, func_ea=0x3d5d0, label=certain)
 *        call: SetValue("sys.sched.wifi.timeType", v7);
 *    - websGetVar (arg=ret, call_ea=0x3d6ac, func_ea=source, label=source)
 *        call: v7 = websGetVar(wp, "timeType", "0");
 * ===================================================== */


/* Function: getSchedWifi @ 0x3D254 */
void __fastcall getSchedWifi(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Object; // r5
  wlan_switch_state *v4; // r4
  cJSON *Number; // r0
  cJSON *v6; // r0
  cJSON *String; // r0
  cJSON *v8; // r0
  cJSON *v9; // r0
  cJSON *v10; // r0
  cJSON *v11; // r0
  void *v12; // r0
  const char *wifi_workmode; // r0
  cJSON *v14; // r0
  cJSON *v15; // r2
  char *v16; // r5
  time_t time_now; // [sp+24h] [bp-64h] BYREF
  char timeType[8]; // [sp+28h] [bp-60h] BYREF
  char power_manage_enable[8]; // [sp+30h] [bp-58h] BYREF
  char wl_mode[16]; // [sp+38h] [bp-50h] BYREF
  char day[32]; // [sp+48h] [bp-40h] BYREF
  char sleep_start_time[32]; // [sp+68h] [bp-20h] BYREF
  char sleep_end_time[36]; // [sp+88h] [bp+0h] BYREF

  *(_DWORD *)timeType = 32;
  *(_DWORD *)&timeType[4] = 0;
  memset(day, 0, sizeof(day));
  memset(sleep_start_time, 0, sizeof(sleep_start_time));
  memset(sleep_end_time, 0, 0x20u);
  memset(power_manage_enable, 0, sizeof(power_manage_enable));
  Object = cJSON_CreateObject();
  v4 = (wlan_switch_state *)malloc(0x19u);
  get_wlan_switch_state(0, v4);
  GetValue("sys.sched.wifi.timeType", timeType);
  sprintf(
    day,
    "%d,%d,%d,%d,%d,%d,%d",
    v4->repeats[0],
    v4->repeats[1],
    v4->repeats[2],
    v4->repeats[3],
    v4->repeats[4],
    v4->repeats[5],
    v4->repeats[6]);
  GetValue("sys.powersleep.enable", power_manage_enable);
  GetValue("sys.powersleep.start_time", sleep_start_time);
  if ( !sleep_start_time[0] )
    strcpy(sleep_start_time, "00:00");
  GetValue("sys.powersleep.end_time", sleep_end_time);
  if ( !sleep_end_time[0] )
    strcpy(sleep_end_time, "07:00");
  strcat(sleep_start_time, "-");
  strcat(sleep_start_time, sleep_end_time);
  if ( !power_manage_enable[0] || !strcmp(power_manage_enable, "0") )
    strcpy(sleep_start_time, &byte_794DF);
  Number = cJSON_CreateNumber((double)v4->switch_state);
  cJSON_AddItemToObject(Object, "wifiEn", Number);
  v6 = cJSON_CreateNumber((double)v4->scheduler_state);
  cJSON_AddItemToObject(Object, "schedWifiEnable", v6);
  String = cJSON_CreateString(v4->begin_time);
  cJSON_AddItemToObject(Object, "schedStartTime", String);
  v8 = cJSON_CreateString(v4->end_time);
  cJSON_AddItemToObject(Object, "schedEndTime", v8);
  v9 = cJSON_CreateString(timeType);
  cJSON_AddItemToObject(Object, "timeType", v9);
  v10 = cJSON_CreateString(day);
  cJSON_AddItemToObject(Object, "day", v10);
  v11 = cJSON_CreateString(sleep_start_time);
  cJSON_AddItemToObject(Object, "powerSaveTime", v11);
  v12 = memset(wl_mode, 0, sizeof(wl_mode));
  wifi_workmode = (const char *)get_wifi_workmode(v12);
  strcpy(wl_mode, wifi_workmode);
  v14 = cJSON_CreateString(wl_mode);
  cJSON_AddItemToObject(Object, "wl_mode", v14);
  time(&time_now);
  if ( localtime(&time_now)->tm_year > 100 )
    v15 = cJSON_CreateString("1");
  else
    v15 = cJSON_CreateString("0");
  cJSON_AddItemToObject(Object, "timeUp", v15);
  v16 = cJSON_Object_2String(Object);
  free(v4);
  websTransfer(wp, v16);
}


/* Function: setSchedWifi @ 0x3D5D0 */
void __fastcall setSchedWifi(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r7
  char_t *v5; // r10
  char_t *v6; // r9
  char_t *v7; // r8
  char_t *v8; // r11
  int mibname; // r0
  char *v10; // r8
  int v11; // r0
  _BOOL4 v12; // r7
  _BYTE *v13; // r1
  int i; // r3
  int v15; // r2
  char_t *fmt; // [sp+0h] [bp-288h]
  char_t *fmta; // [sp+0h] [bp-288h]
  char *src; // [sp+1Ch] [bp-26Ch]
  char wifi_enable[8]; // [sp+24h] [bp-264h] BYREF
  char v20[4]; // [sp+2Ch] [bp-25Ch] BYREF
  int v21; // [sp+30h] [bp-258h]
  char s[16]; // [sp+34h] [bp-254h] BYREF
  int switch_day[7]; // [sp+44h] [bp-244h] BYREF
  char mib_name[256]; // [sp+60h] [bp-228h] BYREF
  char parm[256]; // [sp+160h] [bp-128h] BYREF

  memset(wifi_enable, 0, sizeof(wifi_enable));
  switch_day[0] = 1;
  switch_day[1] = 1;
  switch_day[2] = 1;
  switch_day[3] = 1;
  switch_day[4] = 1;
  switch_day[5] = 1;
  switch_day[6] = 1;
  memset(mib_name, 0, sizeof(mib_name));
  memset(parm, 0, sizeof(parm));
  Var = websGetVar(wp, "schedWifiEnable", "1");
  v5 = websGetVar(wp, "schedStartTime", &byte_794DF);
  v6 = websGetVar(wp, "schedEndTime", &byte_794DF);
  v7 = websGetVar(wp, "timeType", "0");
  v8 = websGetVar(wp, "day", "1,1,1,1,1,1,1");
  mibname = wifi_get_mibname("wlan", "enable", mib_name);
  GetValue(mibname, wifi_enable);
  if ( !wifi_enable[0] )
    strcpy(wifi_enable, "1");
  if ( atoi(v7) )
    _isoc99_sscanf(
      v8,
      "%d,%d,%d,%d,%d,%d,%d",
      switch_day,
      &switch_day[1],
      &switch_day[2],
      &switch_day[3],
      &switch_day[4],
      &switch_day[5],
      &switch_day[6]);
  SetValue("sys.sched.wifi.timeType", v7);
  v10 = (char *)malloc(0x19u);
  v11 = atoi(Var);
  src = (char *)v11;
  if ( v10 )
  {
    *v10 = atoi(wifi_enable) != 0;
    v12 = atoi(Var) != 0;
    v10[1] = v12;
    strcpy(v10 + 2, v5);
    strcpy(v10 + 10, v6);
    v13 = v10 + 17;
    for ( i = 0; i != 7; ++i )
    {
      v15 = switch_day[i];
      *++v13 = v15 != 0;
    }
    memset(s, 0, sizeof(s));
    *(_DWORD *)v20 = 0;
    v21 = 0;
    sprintf(v20, "%d", v12);
    sprintf(
      s,
      "%d,%d,%d,%d,%d,%d,%d",
      (unsigned __int8)v10[18],
      (unsigned __int8)v10[19],
      (unsigned __int8)v10[20],
      (unsigned __int8)v10[21],
      (unsigned __int8)v10[22],
      (unsigned __int8)v10[23],
      (unsigned __int8)v10[24]);
    SetValue("sys.sched.wifi.start", v10 + 2);
    SetValue("sys.sched.wifi.end", v10 + 10);
    SetValue("sys.sched.wifi.enable", v20);
    SetValue("sys.sched.wifi.repeats", s);
    free(v10);
  }
  CommitCfm(v11);
  if ( src )
  {
    sprintf(parm, "op=%d", 1);
    send_msg_to_netctrl(62, parm);
  }
  websWrite(wp, fmt);
  websWrite(wp, fmta);
  websDone(wp, 200);
}
