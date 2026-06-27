/* =====================================================
 *  Path 25
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - setSchedWifi (arg=1, call_ea=0x3d7c4, func_ea=0x3d5d0, label=needs_check)
 *        call: strcpy(v10 + 2, v5);
 *    - websGetVar (arg=ret, call_ea=0x3d67c, func_ea=source, label=source)
 *        call: v5 = websGetVar(wp, "schedStartTime", &byte_794DF);
 * ===================================================== */


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
