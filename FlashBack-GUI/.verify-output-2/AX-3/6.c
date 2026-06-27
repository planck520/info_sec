/* =====================================================
 *  Path 6
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - get_parentControl_list_Info (arg=1, call_ea=0x47634, func_ea=0x47454, label=certain)
 *        call: strcpy(new_pc_info->urls, v14);
 *    - websGetVar (arg=ret, call_ea=0x474fc, func_ea=source, label=source)
 *        call: v14 = websGetVar(wp, "urls", &byte_794DF);
 * ===================================================== */


/* Function: get_parentControl_list_Info @ 0x47454 */
void __fastcall get_parentControl_list_Info(webs_t wp, parent_control_info *new_pc_info)
{
  char_t *Var; // r9
  char_t *v5; // r8
  char_t *v6; // r10
  char_t *v7; // r11
  char_t *v8; // r6
  char_t *v9; // r5
  parent_control_info *v10; // r3
  int i; // r2
  bool v12; // r0
  int v13; // r1
  char *v14; // [sp+18h] [bp-Ch]
  char *src; // [sp+1Ch] [bp-8h]
  int switch_day[8]; // [sp+24h] [bp+0h] BYREF

  memset(switch_day, 0, 0x1Cu);
  src = websGetVar(wp, "deviceId", &byte_794DF);
  Var = websGetVar(wp, "enable", &byte_794DF);
  v5 = websGetVar(wp, "time", &byte_794DF);
  v6 = websGetVar(wp, "url_enable", &byte_794DF);
  v14 = websGetVar(wp, "urls", &byte_794DF);
  v7 = websGetVar(wp, "day", &byte_794DF);
  v8 = websGetVar(wp, "block", &byte_794DF);
  v9 = websGetVar(wp, "limit_type", "1");
  strcpy((char *)new_pc_info->mac_addr, src);
  strcpy(new_pc_info->time, v5);
  _isoc99_sscanf(
    v7,
    "%d,%d,%d,%d,%d,%d,%d",
    switch_day,
    &switch_day[1],
    &switch_day[2],
    &switch_day[3],
    &switch_day[4],
    &switch_day[5],
    &switch_day[6]);
  v10 = (parent_control_info *)&new_pc_info->time[31];
  if ( switch_day[0]
    || switch_day[1]
    || switch_day[2]
    || switch_day[3]
    || switch_day[4]
    || switch_day[5]
    || switch_day[6]
    || *v8 )
  {
    for ( i = 0; i != 7; ++i )
    {
      v13 = switch_day[i];
      v10->pc_mac_en = v13 != 0;
      v10 = (parent_control_info *)((char *)v10 + 1);
    }
  }
  else
  {
    do
    {
      v10->pc_mac_en = 1;
      v10 = (parent_control_info *)((char *)v10 + 1);
    }
    while ( v10 != (parent_control_info *)&new_pc_info->repeats[6] );
  }
  new_pc_info->time_id = atoi(v5);
  strcpy(new_pc_info->urls, v14);
  new_pc_info->url_enable = atoi(v6) != 0;
  v12 = atoi(Var) != 0;
  new_pc_info->pc_mac_en = 0;
  new_pc_info->pc_en = v12;
  new_pc_info->limit_type = atoi(v9) != 0;
}
