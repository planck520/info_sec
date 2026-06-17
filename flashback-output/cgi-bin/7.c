/* =====================================================
 *  Path 7
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - sub_41AB08 (arg=1, call_ea=0x41ac68, func_ea=0x41ab08, label=certain)
 *        call: strcpy(v14, v7);
 *    - websGetVar (arg=ret, call_ea=0x41ac50, func_ea=source, label=source)
 *        call: v7 = websGetVar(ObjectItem, "File", &byte_431360);
 * ===================================================== */


/* Function: sub_41AB08 @ 0x41AB08 */
int __fastcall sub_41AB08(int a1)
{
  int Object; // $s1
  int Var; // $s2
  int ObjectItem; // $s0
  int v5; // $s6
  int v6; // $s7
  int v7; // $v0
  int v8; // $s4
  int v9; // $s3
  int String; // $v0
  int v11; // $v0
  const char *v12; // $s0
  _BYTE v14[204800]; // [sp+18h] [-6402Ch] BYREF
  _BYTE v15[204800]; // [sp+32018h] [-3202Ch] BYREF
  _BYTE v16[44]; // [sp+64018h] [-2Ch] BYREF

  memset(v14, 0, sizeof(v14));
  memset(v15, 0, sizeof(v15));
  Object = cJSON_CreateObject();
  Var = websGetVar(a1, "Action", &byte_431360);
  ObjectItem = cJSON_GetObjectItem(a1, "data");
  if ( strcmp(Var, "GetCustomModule") )
    goto LABEL_5;
  v5 = websGetVar(ObjectItem, "FileMd5", &byte_431360);
  v6 = websGetVar(ObjectItem, "FileUrl", &byte_431360);
  v7 = websGetVar(ObjectItem, "File", &byte_431360);
  strcpy(v14, v7);
  v8 = base64_decode(v14, v15);
  v9 = fopen("/tmp/custom_module", "wb");
  fwrite(v15, v8, 1, v9);
  fclose(v9);
  memset(v16, 0, 33);
  Cal_file_md5("/tmp/custom_module", v16);
  if ( strcmp(v5, v16) )
    goto LABEL_5;
  if ( strstr(v6, "custom.cgi") )
  {
    system("mv /tmp/custom_module /tmp/custom.cgi");
    system("chmod +x  /tmp/custom.cgi");
    String = cJSON_CreateString("Success");
    cJSON_AddItemToObject(Object, "Result", String);
  }
  else
  {
LABEL_5:
    v11 = cJSON_CreateString("Fail");
    cJSON_AddItemToObject(Object, "Result", v11);
  }
  v12 = (const char *)cJSON_Print(Object);
  printf("%s", v12);
  cJSON_Delete(Object);
  free(v12);
  return 1;
}
