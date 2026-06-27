/* =====================================================
 *  Path 17
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - GetParentControlInfo (arg=1, call_ea=0x46770, func_ea=0x466f4, label=certain)
 *        call: strcpy((char *)v5->mac_addr, src);
 *    - websGetVar (arg=ret, call_ea=0x46744, func_ea=source, label=source)
 *        call: src = websGetVar(wp, "mac", &byte_794DF);
 * ===================================================== */


/* Function: GetParentControlInfo @ 0x466F4 */
void __fastcall GetParentControlInfo(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Object; // r5
  parent_control_info *v5; // r4
  cJSON *String; // r0
  const char *v7; // r1
  cJSON *v8; // r2
  cJSON *Number; // r0
  cJSON *v10; // r0
  cJSON *v11; // r0
  cJSON *v12; // r0
  cJSON *v13; // r0
  cJSON *v14; // r0
  char *v15; // r5
  char *src; // [sp+1Ch] [bp-44h]
  int ruleid; // [sp+24h] [bp-3Ch] BYREF
  char day[16]; // [sp+28h] [bp-38h] BYREF

  Object = cJSON_CreateObject();
  memset(day, 0, sizeof(day));
  ruleid = 0;
  src = websGetVar(wp, "mac", &byte_794DF);
  v5 = (parent_control_info *)malloc(0x254u);
  memset(v5, 0, sizeof(parent_control_info));
  strcpy((char *)v5->mac_addr, src);
  if ( getparentcontrolinfo(0, &ruleid, v5) == -1 )
  {
    String = cJSON_CreateString((const char *)v5->mac_addr);
    v7 = "mac";
    v8 = String;
  }
  else
  {
    sprintf(
      day,
      "%d,%d,%d,%d,%d,%d,%d",
      v5->repeats[0],
      v5->repeats[1],
      v5->repeats[2],
      v5->repeats[3],
      v5->repeats[4],
      v5->repeats[5],
      v5->repeats[6]);
    if ( !v5->time[0] )
      strcpy(v5->time, "19:00-21:00");
    Number = cJSON_CreateNumber((double)v5->pc_en);
    cJSON_AddItemToObject(Object, "enable", Number);
    v10 = cJSON_CreateString((const char *)v5->mac_addr);
    cJSON_AddItemToObject(Object, "mac", v10);
    v11 = cJSON_CreateNumber((double)v5->url_enable);
    cJSON_AddItemToObject(Object, "url_enable", v11);
    v12 = cJSON_CreateString(v5->urls);
    cJSON_AddItemToObject(Object, "urls", v12);
    v13 = cJSON_CreateString(v5->time);
    cJSON_AddItemToObject(Object, "time", v13);
    v14 = cJSON_CreateString(day);
    cJSON_AddItemToObject(Object, "day", v14);
    v8 = cJSON_CreateNumber((double)v5->limit_type);
    v7 = "limit_type";
  }
  cJSON_AddItemToObject(Object, v7, v8);
  v15 = cJSON_Object_2String(Object);
  free(v5);
  websTransfer(wp, v15);
}
