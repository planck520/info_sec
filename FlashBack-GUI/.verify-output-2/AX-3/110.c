/* =====================================================
 *  Path 110
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formGetRebootTimer (arg=1, call_ea=0x57e00, func_ea=0x57d7c, label=certain)
 *        call: GetValue("sys.schedulereboot.start_time", start_time);
 *    - formSetRebootTimer (arg=1, call_ea=0x57be8, func_ea=0x57a74, label=needs_check)
 *        call: SetValue("sys.schedulereboot.start_time", v6);
 *    - websGetVar (arg=ret, call_ea=0x57af0, func_ea=source, label=source)
 *        call: v6 = websGetVar(wp, "rebootTime", "02:00");
 * ===================================================== */


/* Function: formGetRebootTimer @ 0x57D7C */
void __fastcall formGetRebootTimer(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Object; // r4
  cJSON *String; // r0
  cJSON *v6; // r0
  cJSON *v7; // r0
  const char *v8; // r0
  cJSON *v9; // r0
  cJSON *v10; // r2
  cJSON *v11; // r0
  char *v12; // r5
  time_t time_now; // [sp+0h] [bp-4h] BYREF
  char enable[8]; // [sp+4h] [bp+0h] BYREF
  char reboot_speed[8]; // [sp+Ch] [bp+8h] BYREF
  char delay_reboot[8]; // [sp+14h] [bp+10h] BYREF
  char start_time[12]; // [sp+1Ch] [bp+18h] BYREF
  char end_time[12]; // [sp+28h] [bp+24h] BYREF
  char reboot_time[24]; // [sp+34h] [bp+30h] BYREF

  memset(enable, 0, sizeof(enable));
  memset(reboot_time, 0, 0x14u);
  memset(start_time, 0, 10);
  memset(end_time, 0, 10);
  memset(reboot_speed, 0, sizeof(reboot_speed));
  memset(delay_reboot, 0, sizeof(delay_reboot));
  GetValue("sys.schedulereboot.enable", enable);
  GetValue("sys.schedulereboot.start_time", start_time);
  GetValue("sys.schedulereboot.end_time", end_time);
  GetValue("sys.schedulereboot.max_speed", reboot_speed);
  GetValue("sys.schedulereboot.type", delay_reboot);
  Object = cJSON_CreateObject();
  String = cJSON_CreateString(enable);
  cJSON_AddItemToObject(Object, "autoRebootEn", String);
  sprintf(reboot_time, "%s-%s", start_time, end_time);
  v6 = cJSON_CreateString(reboot_time);
  cJSON_AddItemToObject(Object, "time", v6);
  v7 = cJSON_CreateString(start_time);
  cJSON_AddItemToObject(Object, "rebootTime", v7);
  if ( !strcmp(delay_reboot, "1") )
    v8 = "true";
  else
    v8 = "false";
  v9 = cJSON_CreateString(v8);
  cJSON_AddItemToObject(Object, "delayRebootEn", v9);
  time(&time_now);
  if ( localtime(&time_now)->tm_year > 100 )
    v10 = cJSON_CreateString("1");
  else
    v10 = cJSON_CreateString("0");
  cJSON_AddItemToObject(Object, "timeUp", v10);
  v11 = cJSON_CreateString(reboot_speed);
  cJSON_AddItemToObject(Object, "speed", v11);
  v12 = cJSON_Print(Object);
  cJSON_Delete(Object);
  websWrite(wp, (char_t *)time_now);
  websWrite(wp, (char_t *)time_now);
  free(v12);
  websDone(wp, 200);
}


/* Function: formSetRebootTimer @ 0x57A74 */
void __fastcall formSetRebootTimer(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r7
  char_t *v5; // r8
  char_t *v6; // r6
  bool v7; // zf
  char *v8; // r1
  int v9; // r0
  const char *v10; // r1
  char_t *fmt; // [sp+0h] [bp-50h]
  char_t *fmta; // [sp+0h] [bp-50h]
  char enable_old[4]; // [sp+Ch] [bp-44h] BYREF
  int v14; // [sp+10h] [bp-40h] BYREF
  char_t *v15; // [sp+14h] [bp-3Ch] BYREF
  char delay_reboot_old[8]; // [sp+18h] [bp-38h] BYREF
  char reboot_time_old[8]; // [sp+20h] [bp-30h] BYREF
  _DWORD v18[10]; // [sp+28h] [bp-28h] BYREF

  *(_WORD *)enable_old = 0;
  memset(delay_reboot_old, 0, sizeof(delay_reboot_old));
  memset(reboot_time_old, 0, sizeof(reboot_time_old));
  Var = websGetVar(wp, "autoRebootEn", "1");
  v5 = websGetVar(wp, "delayRebootEn", "true");
  v6 = websGetVar(wp, "rebootTime", "02:00");
  GetValue("sys.schedulereboot.enable", enable_old);
  GetValue("sys.schedulereboot.type", delay_reboot_old);
  GetValue("sys.schedulereboot.start_time", reboot_time_old);
  if ( Var && (unsigned int)atoi(Var) <= 1 )
  {
    v7 = v6 == 0;
    if ( v6 )
      v7 = v5 == 0;
    if ( !v7 && (strcmp(Var, enable_old) || strcmp(v5, delay_reboot_old) || strcmp(v6, reboot_time_old)) )
    {
      SetValue("sys.schedulereboot.enable", Var);
      if ( !strcmp(v5, "true") )
        v8 = "1";
      else
        v8 = "0";
      SetValue("sys.schedulereboot.type", v8);
      SetValue("sys.schedulereboot.start_time", v6);
      v14 = 0;
      v15 = 0;
      v18[0] = 0;
      v18[1] = 0;
      v9 = _isoc99_sscanf(v6, "%d:%d", &v14, &v15);
      if ( v9 == 2 )
      {
        v14 = (v14 + 2) % 24;
        sprintf((char *)v18, "%d%d:%d", v14 / 10, v14 % 10, v15);
        if ( !strcmp(v6, "02:00") )
          v10 = "05:30";
        else
          v10 = (const char *)v18;
        v9 = SetValue("sys.schedulereboot.end_time", v10);
      }
      if ( CommitCfm(v9) )
      {
        printf("[he debug]:%s,%d--set msg to update the rebootTimer!\n", "formSetRebootTimer", 97);
        send_msg_to_netctrl(32, 0);
      }
    }
  }
  websWrite(wp, fmt);
  websWrite(wp, fmta);
  websDone(wp, 200);
}
