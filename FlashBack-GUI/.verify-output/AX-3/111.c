/* =====================================================
 *  Path 111
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formGetSchedLed (arg=1, call_ea=0x4f628, func_ea=0x4f580, label=certain)
 *        call: GetValue("sys.sched.led.time", sched_led_time);
 *    - formSetSchedLed (arg=1, call_ea=0x4f4bc, func_ea=0x4f428, label=certain)
 *        call: SetValue("sys.sched.led.time", v5);
 *    - websGetVar (arg=ret, call_ea=0x4f484, func_ea=source, label=source)
 *        call: v5 = websGetVar(wp, "time", "22:00-06:00");
 * ===================================================== */


/* Function: formGetSchedLed @ 0x4F580 */
void __fastcall formGetSchedLed(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Object; // r4
  cJSON *String; // r0
  cJSON *v6; // r0
  cJSON *v7; // r0
  cJSON *v8; // r0
  cJSON *v9; // r2
  char *v10; // r0
  time_t time_now; // [sp+4h] [bp-14Ch] BYREF
  char power_manage_enable[16]; // [sp+8h] [bp-148h] BYREF
  char close_type[16]; // [sp+18h] [bp-138h] BYREF
  char sched_led_type[64]; // [sp+28h] [bp-128h] BYREF
  char sched_led_time[64]; // [sp+68h] [bp-E8h] BYREF
  char sleep_start_time[64]; // [sp+A8h] [bp-A8h] BYREF
  char sleep_end_time[64]; // [sp+E8h] [bp-68h] BYREF

  Object = cJSON_CreateObject();
  memset(sched_led_type, 0, sizeof(sched_led_type));
  memset(sched_led_time, 0, sizeof(sched_led_time));
  memset(sleep_start_time, 0, sizeof(sleep_start_time));
  memset(sleep_end_time, 0, sizeof(sleep_end_time));
  memset(power_manage_enable, 0, sizeof(power_manage_enable));
  memset(close_type, 0, sizeof(close_type));
  GetValue("sys.sched.led.type", sched_led_type);
  GetValue("sys.sched.led.time", sched_led_time);
  GetValue("sys.sched.led.closetype", close_type);
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
  String = cJSON_CreateString(sched_led_type);
  cJSON_AddItemToObject(Object, "ledType", String);
  v6 = cJSON_CreateString(sched_led_time);
  cJSON_AddItemToObject(Object, "time", v6);
  v7 = cJSON_CreateString(close_type);
  cJSON_AddItemToObject(Object, "ledCloseType", v7);
  v8 = cJSON_CreateString(sleep_start_time);
  cJSON_AddItemToObject(Object, "powerSaveTime", v8);
  time(&time_now);
  if ( localtime(&time_now)->tm_year > 100 )
    v9 = cJSON_CreateString("1");
  else
    v9 = cJSON_CreateString("0");
  cJSON_AddItemToObject(Object, "timeUp", v9);
  v10 = cJSON_Object_2String(Object);
  websTransfer(wp, v10);
}


/* Function: formSetSchedLed @ 0x4F428 */
void __fastcall formSetSchedLed(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r7
  char_t *v5; // r9
  char_t *v6; // r8
  int v7; // r0
  char parm[256]; // [sp+0h] [bp-120h] BYREF

  memset(parm, 0, sizeof(parm));
  Var = websGetVar(wp, "ledType", "open");
  v5 = websGetVar(wp, "time", "22:00-06:00");
  v6 = websGetVar(wp, "ledCloseType", "allClose");
  SetValue("sys.sched.led.type", Var);
  SetValue("sys.sched.led.time", v5);
  v7 = strcmp(Var, "time");
  if ( !v7 )
    v7 = SetValue("sys.sched.led.closetype", v6);
  if ( CommitCfm(v7) )
  {
    sprintf(parm, "op=%d,string_info=led_control", 1);
    send_msg_to_netctrl(62, parm);
  }
  websWrite(wp, *(char_t **)parm);
  websWrite(wp, *(char_t **)parm);
  websDone(wp, 200);
}
