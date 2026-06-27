/* =====================================================
 *  Path 8
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - fromSetSysTime (arg=1, call_ea=0x57450, func_ea=0x57254, label=needs_check)
 *        call: strcpy(&v34[16], v7);
 *    - websGetVar (arg=ret, call_ea=0x57368, func_ea=source, label=source)
 *        call: v7 = websGetVar(wp, "ntpServer", "time.windows.com");
 * ===================================================== */


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
