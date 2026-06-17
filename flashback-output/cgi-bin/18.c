/* =====================================================
 *  Path 18
 *  vuln_type = CWE-120
 *  sink_func = memset
 *  source_func = sscanf
 *  Hops:
 *    - memset (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - sub_404E14 (arg=0, call_ea=0x40515c, func_ea=0x404e14, label=needs_check)
 *        call: memset(v15, 0, sizeof(v15));
 *    - sscanf (arg=0, call_ea=0x405144, func_ea=source, label=source)
 *        call: sscanf(v15, "%s %s %s %s %s %s %s %s %s", v43, &v16, v24, &v27, v25, v26, &v35, v44, &v45);
 * ===================================================== */


/* Function: sub_404E14 @ 0x404E14 */
int sub_404E14()
{
  int v0; // $v0
  int v1; // $s5
  int v2; // $s4
  int Array; // $s6
  int Object; // $s1
  int Number; // $v0
  int String; // $v0
  int v7; // $v0
  int v8; // $v0
  int v9; // $v0
  int v10; // $v0
  int v11; // $v0
  int v12; // $s0
  _BYTE v14[256]; // [sp+38h] [-448h] BYREF
  _BYTE v15[512]; // [sp+138h] [-348h] BYREF
  int v16; // [sp+338h] [-148h] BYREF
  int v17; // [sp+33Ch] [-144h]
  int v18; // [sp+340h] [-140h]
  int v19; // [sp+344h] [-13Ch]
  int v20; // [sp+348h] [-138h]
  int v21; // [sp+34Ch] [-134h]
  int v22; // [sp+350h] [-130h]
  int v23; // [sp+354h] [-12Ch]
  _DWORD v24[8]; // [sp+358h] [-128h] BYREF
  _DWORD v25[8]; // [sp+378h] [-108h] BYREF
  _DWORD v26[8]; // [sp+398h] [-E8h] BYREF
  int v27; // [sp+3B8h] [-C8h] BYREF
  int v28; // [sp+3BCh] [-C4h]
  int v29; // [sp+3C0h] [-C0h]
  int v30; // [sp+3C4h] [-BCh]
  int v31; // [sp+3C8h] [-B8h]
  int v32; // [sp+3CCh] [-B4h]
  int v33; // [sp+3D0h] [-B0h]
  int v34; // [sp+3D4h] [-ACh]
  int v35; // [sp+3D8h] [-A8h] BYREF
  int v36; // [sp+3DCh] [-A4h]
  int v37; // [sp+3E0h] [-A0h]
  int v38; // [sp+3E4h] [-9Ch]
  int v39; // [sp+3E8h] [-98h]
  int v40; // [sp+3ECh] [-94h]
  int v41; // [sp+3F0h] [-90h]
  int v42; // [sp+3F4h] [-8Ch]
  _DWORD v43[2]; // [sp+3F8h] [-88h] BYREF
  _BYTE v44[64]; // [sp+400h] [-80h] BYREF
  int v45; // [sp+440h] [-40h] BYREF
  int v46; // [sp+444h] [-3Ch]
  int v47; // [sp+448h] [-38h]
  int v48; // [sp+44Ch] [-34h]
  int v49; // [sp+450h] [-30h]
  int v50; // [sp+454h] [-2Ch]
  int v51; // [sp+458h] [-28h]
  int v52; // [sp+45Ch] [-24h]
  const char *v53; // [sp+460h] [-20h]
  const char *v54; // [sp+464h] [-1Ch]
  char *v55; // [sp+468h] [-18h]
  const char *v56; // [sp+46Ch] [-14h]
  const char *v57; // [sp+470h] [-10h]
  char *v58; // [sp+474h] [-Ch]
  char *v59; // [sp+478h] [-8h]

  memset(v14, 0, sizeof(v14));
  memset(v15, 0, sizeof(v15));
  v16 = 0;
  v17 = 0;
  v18 = 0;
  v19 = 0;
  v20 = 0;
  v21 = 0;
  v22 = 0;
  v23 = 0;
  memset(v24, 0, sizeof(v24));
  memset(v25, 0, sizeof(v25));
  memset(v26, 0, sizeof(v26));
  v27 = 0;
  v28 = 0;
  v29 = 0;
  v30 = 0;
  v31 = 0;
  v32 = 0;
  v33 = 0;
  v34 = 0;
  v35 = 0;
  v36 = 0;
  v37 = 0;
  v38 = 0;
  v39 = 0;
  v40 = 0;
  v41 = 0;
  v42 = 0;
  v43[0] = 0;
  v43[1] = 0;
  memset(v44, 0, sizeof(v44));
  v45 = 0;
  v46 = 0;
  v47 = 0;
  v48 = 0;
  v49 = 0;
  v50 = 0;
  v51 = 0;
  v52 = 0;
  if ( (unsigned int)(nvram_get_int("tnt_enable") - 1) < 2
    && (getCmdStr("cat /var/run/tnt_stat.pid", v15, 512), pids("tnt_stat"))
    && (killall("tnt_stat", 16), usleep(100000), v0 = fopen("/var/run/tnt.edge_list", "r"), (v1 = v0) != 0) )
  {
    fgets(v14, 256, v0);
    v2 = 0;
    Array = cJSON_CreateArray();
    cJSON_CreateArray();
    v53 = "tnt_enable";
    v54 = "deviceName";
    v59 = &byte_431360;
    v55 = "status";
    v56 = "deviceId";
    v57 = "mac";
    v58 = "ip";
    while ( fgets(v15, 512, v1) )
    {
      memset(v44, 0, sizeof(v44));
      v45 = 0;
      v46 = 0;
      v47 = 0;
      v48 = 0;
      v49 = 0;
      v50 = 0;
      v51 = 0;
      v52 = 0;
      sscanf(v15, "%s %s %s %s %s %s %s %s %s", v43, &v16, v24, &v27, v25, v26, &v35, v44, &v45);
      memset(v15, 0, sizeof(v15));
      ++v2;
      Object = cJSON_CreateObject();
      Number = cJSON_CreateNumber();
      cJSON_AddItemToObject(Object, "idx", Number);
      if ( nvram_get_int(v53) == 1 && v2 >= 2 && v44[0] && !(_BYTE)v45 )
      {
        String = cJSON_CreateString(v59);
        cJSON_AddItemToObject(Object, v54, String);
      }
      else
      {
        v7 = cJSON_CreateString(v44);
        cJSON_AddItemToObject(Object, v54, v7);
      }
      v8 = cJSON_CreateString(v43);
      cJSON_AddItemToObject(Object, v55, v8);
      v9 = cJSON_CreateString(v24);
      cJSON_AddItemToObject(Object, v56, v9);
      v10 = cJSON_CreateString(v25);
      cJSON_AddItemToObject(Object, v57, v10);
      v11 = cJSON_CreateString(v26);
      cJSON_AddItemToObject(Object, v58, v11);
      cJSON_AddItemToArray(Array, Object);
    }
    fclose(v1);
    v12 = cJSON_Print(Array);
    puts(v12);
    cJSON_Delete(Array);
    free(v12);
    return 1;
  }
  else
  {
    puts("[]\n");
    cJSON_Delete(0);
    free(0);
    return 1;
  }
}
