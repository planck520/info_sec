/* =====================================================
 *  Path 4
 *  vuln_type = CWE-22
 *  sink_func = fopen
 *  source_func = websGetVar
 *  Hops:
 *    - fopen (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - sub_425D60 (arg=0, call_ea=0x425e70, func_ea=0x425d60, label=needs_check)
 *        call: v9 = fopen(v7, "r");
 *    - websGetVar (arg=ret, call_ea=0x425da8, func_ea=source, label=source)
 *        call: Var = websGetVar(a1, "FileName", &byte_431360);
 * ===================================================== */


/* Function: sub_425D60 @ 0x425D60 */
int __fastcall sub_425D60(int a1)
{
  int Var; // $s2
  int v3; // $s0
  int Object; // $s1
  int v5; // $s3
  int v6; // $v0
  int v7; // $s4
  int v8; // $s2
  int v9; // $v0
  int v10; // $s0
  int v11; // $v0
  int String; // $v0
  const char *v13; // $s0
  const char *v15; // [sp+18h] [-10h] BYREF
  const char *v16; // [sp+1Ch] [-Ch]
  int v17; // [sp+20h] [-8h]
  int v18; // [sp+24h] [-4h]

  Var = websGetVar(a1, "FileName", &byte_431360);
  v3 = websGetVar(a1, "ContentLength", &byte_431360);
  Object = cJSON_CreateObject();
  v5 = strtol(v3, 0, 10) + 1;
  if ( v5 >= 1000 )
  {
    v7 = Var;
    v8 = malloc(v5);
    memset(v8, 0, v5);
    v9 = fopen(v7, "r");
    v10 = v9;
    if ( v9 && (fread(v8, 1, v5, v9), fclose(v10), !strncmp(v8, "HDR2", 4)) )
    {
      doSystem("killall %s %s", "-q", "watchdog");
      sleep(1);
      v15 = "/usr/sbin/nvram";
      v16 = "restore";
      v17 = v7;
      v18 = 0;
      if ( eval(&v15, 0, 0, 0) )
      {
        v15 = "/sbin/watchdog";
        v16 = 0;
        eval(&v15, 0, 0, 0);
        free(v8);
      }
      else
      {
        nvram_commit();
        unlink(v7);
        String = cJSON_CreateString("1");
        cJSON_AddItemToObject(Object, "settingERR", String);
        doSystem("lktos_reload %s", "reboot");
      }
    }
    else
    {
      v11 = cJSON_CreateString("MSG_config_error");
      cJSON_AddItemToObject(Object, "settingERR", v11);
      free(v8);
    }
  }
  else
  {
    v6 = cJSON_CreateString("MSG_config_error");
    cJSON_AddItemToObject(Object, "settingERR", v6);
  }
  v13 = (const char *)cJSON_Print(Object);
  printf("%s", v13);
  free(v13);
  cJSON_Delete(Object);
  return 1;
}
