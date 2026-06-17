/* =====================================================
 *  Path 6
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - setDefResponse (arg=1, call_ea=0x42bca0, func_ea=0x42bc00, label=needs_check)
 *        call: strcpy(v15, Var);
 *    - websGetVar (arg=ret, call_ea=0x42bc8c, func_ea=source, label=source)
 *        call: Var = websGetVar(JsonConf, "IpAddress", (int)&byte_431360);
 * ===================================================== */


/* Function: setDefResponse @ 0x42BC00 */
int __fastcall setDefResponse(int a1, int a2)
{
  int Object; // $s0
  int JsonConf; // $v0
  int v6; // $s1
  char *Var; // $v0
  int True; // $v0
  int Null; // $v0
  int String; // $v0
  int v11; // $v0
  int v12; // $v0
  int v13; // $s1
  _DWORD v15[9]; // [sp+18h] [-24h] BYREF

  memset(v15, 0, 32);
  Object = cJSON_CreateObject();
  getIfIp("br0", v15);
  JsonConf = getJsonConf(0);
  v6 = JsonConf;
  if ( JsonConf )
  {
    Var = websGetVar(JsonConf, "IpAddress", (int)&byte_431360);
    strcpy(v15, Var);
    cJSON_Delete(v6);
  }
  True = cJSON_CreateTrue();
  cJSON_AddItemToObject(Object, "success", True);
  Null = cJSON_CreateNull();
  cJSON_AddItemToObject(Object, "error", Null);
  String = cJSON_CreateString(v15);
  cJSON_AddItemToObject(Object, "lan_ip", String);
  v11 = cJSON_CreateString(a1);
  cJSON_AddItemToObject(Object, "wtime", v11);
  v12 = cJSON_CreateString(a2);
  cJSON_AddItemToObject(Object, "reserv", v12);
  v13 = cJSON_Print(Object);
  puts(v13);
  cJSON_Delete(Object);
  free(v13);
  return 0;
}
