/* =====================================================
 *  Path 85
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - fromGetSysTime (arg=1, call_ea=0x578d4, func_ea=0x576e8, label=certain)
 *        call: GetValue("sys.timefixper", timeper);
 *    - fromSetSysTime (arg=1, call_ea=0x5740c, func_ea=0x57254, label=needs_check)
 *        call: SetValue("sys.timefixper", v6);
 *    - websGetVar (arg=ret, call_ea=0x5734c, func_ea=source, label=source)
 *        call: v6 = websGetVar(wp, "timePeriod", &byte_794DF);
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


/* Function: fromSetSysTime @ 0x57254 */
void __fastcall fromSetSysTime(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r6
  char_t *v5; // r9
  char_t *v6; // r11
  char_t *v7; // r10
  int v8; // r0
  char_t *v9; // r0
  __time_t v10; // r0
  int v11; // r2
  int v12; // r0
  struct timeval tv; // [sp+18h] [bp-3B8h] BYREF
  _DWORD v14[2]; // [sp+20h] [bp-3B0h] BYREF
  __int16 v15; // [sp+28h] [bp-3A8h]
  _DWORD v16[2]; // [sp+2Ch] [bp-3A4h] BYREF
  __int16 v17; // [sp+34h] [bp-39Ch]
  _DWORD v18[2]; // [sp+38h] [bp-398h] BYREF
  __int16 v19; // [sp+40h] [bp-390h]
  int v20; // [sp+44h] [bp-38Ch] BYREF
  int v21; // [sp+48h] [bp-388h]
  __int16 v22; // [sp+4Ch] [bp-384h]
  int v23; // [sp+50h] [bp-380h] BYREF
  int v24; // [sp+54h] [bp-37Ch]
  int v25; // [sp+58h] [bp-378h]
  int v26; // [sp+5Ch] [bp-374h]
  int v27; // [sp+60h] [bp-370h] BYREF
  int v28; // [sp+64h] [bp-36Ch]
  int v29; // [sp+68h] [bp-368h]
  int v30; // [sp+6Ch] [bp-364h]
  char s[16]; // [sp+70h] [bp-360h] BYREF
  char tmp[256]; // [sp+80h] [bp-350h] BYREF
  SNTP_CFG_STRU cfg; // [sp+180h] [bp-250h] BYREF
  _BYTE v34[276]; // [sp+294h] [bp-13Ch] BYREF

  memset(tmp, 0, sizeof(tmp));
  memset(&cfg, 0, sizeof(cfg));
  Var = websGetVar(wp, "timeType", "sync");
  if ( !strcmp(Var, "sync") )
  {
    v23 = 48;
    v27 = 48;
    v24 = 0;
    v25 = 0;
    v26 = 0;
    v28 = 0;
    v29 = 0;
    v30 = 0;
    v20 = 0;
    v21 = 0;
    memset(s, 0, sizeof(s));
    memset(v34, 0, sizeof(v34));
    v5 = websGetVar(wp, "timeZone", &byte_794DF);
    v6 = websGetVar(wp, "timePeriod", &byte_794DF);
    v7 = websGetVar(wp, "ntpServer", "time.windows.com");
    if ( strchr(v5, 58) )
    {
      _isoc99_sscanf(v5, "%[^:]:%s", &v23, &v27);
    }
    else
    {
      strcpy((char *)&v23, v5);
      strcpy((char *)&v27, "0");
    }
    SetValue("sys.timesyn", "1");
    SetValue("sys.timemode", "auto");
    SetValue("sys.timezone", &v23);
    SetValue("sys.timenextzone", &v27);
    SetValue("sys.timefixper", v6);
    v8 = SetValue("sys.timentpserver", v7);
    if ( CommitCfm(v8) )
    {
      GetValue("sys.timesyn", &v20);
      if ( atoi((const char *)&v20) == 1 )
      {
        strcpy(&v34[16], v7);
        sprintf(s, "op=%d", 3);
      }
      else
      {
        sprintf(s, "op=%d", 2);
      }
      send_msg_to_netctrl(24, s);
      goto LABEL_17;
    }
  }
  else
  {
    if ( strcmp(Var, "manual") )
    {
LABEL_17:
      v11 = 0;
      goto LABEL_18;
    }
    memset(s, 0, sizeof(s));
    v14[0] = 0;
    v14[1] = 0;
    v15 = 0;
    v16[0] = 0;
    v16[1] = 0;
    v17 = 0;
    v18[0] = 0;
    v18[1] = 0;
    v19 = 0;
    v20 = 0;
    v21 = 0;
    v22 = 0;
    v23 = 0;
    v24 = 0;
    LOWORD(v25) = 0;
    v27 = 0;
    v28 = 0;
    LOWORD(v29) = 0;
    v9 = websGetVar(wp, "time", &byte_794DF);
    _isoc99_sscanf(v9, "%[^-]-%[^-]-%[^ ] %[^:]:%[^:]:%s", v14, v16, v18, &v20, &v23, &v27);
    *(_DWORD *)&v34[20] = atoi((const char *)v14) - 1900;
    *(_DWORD *)&v34[16] = atoi((const char *)v16) - 1;
    *(_DWORD *)&v34[12] = atoi((const char *)v18);
    *(_DWORD *)&v34[8] = atoi((const char *)&v20);
    *(_DWORD *)&v34[4] = atoi((const char *)&v23);
    *(_DWORD *)v34 = atoi((const char *)&v27);
    v10 = mktime((struct tm *)v34);
    if ( v10 > 10 )
    {
      tv.tv_sec = v10;
      tv.tv_usec = 0;
      if ( settimeofday(&tv, 0) >= 0 )
      {
        SetValue("sys.timesyn", "0");
        v12 = SetValue("sys.timemode", "hand");
        if ( CommitCfm(v12) )
        {
          sprintf(s, "op=%d", 2);
          send_msg_to_netctrl(24, s);
          v11 = 0;
          goto LABEL_18;
        }
      }
      else
      {
        puts("Set   system   datatime   error!");
      }
    }
  }
  v11 = 1;
LABEL_18:
  sprintf(tmp, "{\"errCode\":%d}", v11);
  websTransfer(wp, tmp);
}
