/* =====================================================
 *  Path 83
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - fromGetSysTime (arg=1, call_ea=0x57798, func_ea=0x576e8, label=certain)
 *        call: GetValue("sys.timezone", timezone);
 *    - fromSysToolTime (arg=1, call_ea=0x5715c, func_ea=0x56f38, label=certain)
 *        call: SetValue("sys.timezone", v4);
 *    - websGetVar (arg=ret, call_ea=0x56fc0, func_ea=source, label=source)
 *        call: v4 = websGetVar(wp, "TZ", &byte_794DF);
 * ===================================================== */


/* Function: fromGetSysTime @ 0x576E8 */
void __fastcall fromGetSysTime(webs_t wp, char_t *path, char_t *query)
{
  struct tm *v4; // r5
  cJSON *Object; // r4
  cJSON *String; // r2
  cJSON *v7; // r0
  cJSON *v8; // r0
  cJSON *v9; // r0
  cJSON *v10; // r0
  const char *v11; // r1
  cJSON *v12; // r0
  char *v13; // r5
  char_t *fmt; // [sp+0h] [bp-20h]
  char_t *fmta; // [sp+0h] [bp-20h]
  time_t time_now; // [sp+1Ch] [bp-4h] BYREF
  char mode[16]; // [sp+20h] [bp+0h] BYREF
  char value[16]; // [sp+30h] [bp+10h] BYREF
  char timezone[16]; // [sp+40h] [bp+20h] BYREF
  char timeper[16]; // [sp+50h] [bp+30h] BYREF
  char timezone_str[16]; // [sp+60h] [bp+40h] BYREF
  char nextzone[16]; // [sp+70h] [bp+50h] BYREF
  char timentpserver[260]; // [sp+80h] [bp+60h] BYREF

  memset(mode, 0, sizeof(mode));
  memset(value, 0, sizeof(value));
  memset(timezone, 0, sizeof(timezone));
  memset(timeper, 0, sizeof(timeper));
  memset(timentpserver, 0, 0x100u);
  memset(timezone_str, 0, sizeof(timezone_str));
  memset(nextzone, 0, sizeof(nextzone));
  GetValue("sys.timezone", timezone);
  GetValue("sys.timenextzone", nextzone);
  time(&time_now);
  if ( !strcmp(nextzone, "10") )
  {
    time_now -= 600;
    printf("nextzone = %s \n", nextzone);
  }
  v4 = localtime(&time_now);
  GetValue("sys.timemode", mode);
  Object = cJSON_CreateObject();
  if ( !strcmp(mode, "hand") )
    String = cJSON_CreateString("manual");
  else
    String = cJSON_CreateString("sync");
  cJSON_AddItemToObject(Object, "timeType", String);
  if ( !strcmp(nextzone, "0") || !nextzone[0] )
    strcpy(nextzone, "00");
  sprintf(timezone_str, "%s:%s", timezone, nextzone);
  v7 = cJSON_CreateString(timezone_str);
  cJSON_AddItemToObject(Object, "timeZone", v7);
  GetValue("sys.timefixper", timeper);
  v8 = cJSON_CreateString(timeper);
  cJSON_AddItemToObject(Object, "timePeriod", v8);
  GetValue("sys.timentpserver", timentpserver);
  v9 = cJSON_CreateString(timentpserver);
  cJSON_AddItemToObject(Object, "ntpServer", v9);
  sprintf(
    value,
    "%d-%02d-%02d %02d:%02d:%02d",
    v4->tm_year + 1900,
    v4->tm_mon + 1,
    v4->tm_mday,
    v4->tm_hour,
    v4->tm_min,
    v4->tm_sec);
  v10 = cJSON_CreateString(value);
  cJSON_AddItemToObject(Object, "time", v10);
  if ( v4->tm_year > 100 )
    v11 = "true";
  else
    v11 = "false";
  strcpy(value, v11);
  v12 = cJSON_CreateString(value);
  cJSON_AddItemToObject(Object, "isSyncInternetTime", v12);
  v13 = cJSON_Print(Object);
  cJSON_Delete(Object);
  websWrite(wp, fmt);
  websWrite(wp, fmta);
  free(v13);
  websDone(wp, 200);
}


/* Function: fromSysToolTime @ 0x56F38 */
void __fastcall fromSysToolTime(webs_t wp, char_t *path, char_t *query)
{
  char_t *v4; // r9
  char_t *v5; // r11
  char_t *v6; // r0
  char_t *v7; // r0
  char_t *v8; // r0
  char_t *v9; // r0
  char_t *v10; // r0
  char_t *v11; // r0
  time_t v12; // r0
  time_t v13; // r5
  char *v14; // r1
  int v15; // r0
  char_t *Var; // [sp+8h] [bp-24h]
  char_t *v17; // [sp+Ch] [bp-20h]
  int v18; // [sp+10h] [bp-1Ch]
  timeval tv; // [sp+14h] [bp-18h] BYREF
  char oldtimezone[8]; // [sp+1Ch] [bp-10h] BYREF
  char timeen[8]; // [sp+24h] [bp-8h] BYREF
  char par[16]; // [sp+2Ch] [bp+0h] BYREF
  tm tm_t; // [sp+3Ch] [bp+10h] BYREF
  SNTP_CFG_STRU cfg; // [sp+68h] [bp+3Ch] BYREF

  memset(oldtimezone, 0, sizeof(oldtimezone));
  memset(timeen, 0, sizeof(timeen));
  memset(par, 0, sizeof(par));
  memset(&cfg, 0, sizeof(cfg));
  Var = websGetVar(wp, "TimeIndex", "1");
  v4 = websGetVar(wp, "TZ", &byte_794DF);
  v5 = websGetVar(wp, "check", &byte_794DF);
  v17 = websGetVar(wp, "SETPRIO", &byte_794DF);
  v6 = websGetVar(wp, "year", &byte_794DF);
  tm_t.tm_year = atoi(v6) - 1900;
  v7 = websGetVar(wp, "month", &byte_794DF);
  tm_t.tm_mon = atoi(v7) - 1;
  v8 = websGetVar(wp, "day", &byte_794DF);
  tm_t.tm_mday = atoi(v8);
  v9 = websGetVar(wp, "hour", &byte_794DF);
  tm_t.tm_hour = atoi(v9);
  v10 = websGetVar(wp, "minute", &byte_794DF);
  tm_t.tm_min = atoi(v10);
  v11 = websGetVar(wp, "second", &byte_794DF);
  tm_t.tm_sec = atoi(v11);
  v12 = mktime(&tm_t);
  if ( v12 > 10 )
  {
    v13 = v12;
    GetValue("sys.timezone", oldtimezone);
    v18 = atoi(v4);
    tv.tv_usec = 0;
    tv.tv_sec = v13 + 3600 * (v18 - atoi(oldtimezone));
    if ( settimeofday(&tv, 0) < 0 )
      puts("Set   system   datatime   error!");
  }
  if ( !strcmp(v5, "on") )
    v14 = "1";
  else
    v14 = "0";
  SetValue("sys.timesyn", v14);
  SetValue("sys.timezone", v4);
  SetValue("sys.timeindex", Var);
  v15 = SetValue("sys.timefixper", v17);
  if ( CommitCfm(v15) )
  {
    GetValue("sys.timesyn", timeen);
    if ( atoi(timeen) == 1 )
      sprintf(par, "op=%d", 3);
    else
      sprintf(par, "op=%d", 2);
    send_msg_to_netctrl(24, par);
  }
  websRedirect(wp, "/system/system_hostname.asp");
}
