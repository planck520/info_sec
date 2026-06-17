/* =====================================================
 *  Path 17
 *  vuln_type = CWE-120
 *  sink_func = memset
 *  source_func = sscanf
 *  Hops:
 *    - memset (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - sub_402A04 (arg=0, call_ea=0x402e14, func_ea=0x402a04, label=needs_check)
 *        call: memset(v30, 0, sizeof(v30));
 *    - sscanf (arg=0, call_ea=0x402c54, func_ea=source, label=source)
 *        call: sscanf(v30, v35, &v14, &v16, &v21, &v18, v29);
 * ===================================================== */


/* Function: sub_402A04 @ 0x402A04 */
int sub_402A04()
{
  int v0; // $v0
  int String; // $v0
  int v2; // $s2
  int v3; // $s4
  int v4; // $s0
  int v5; // $v0
  int v6; // $v0
  int v7; // $v0
  int v8; // $v0
  int v9; // $v0
  int v10; // $v0
  int v11; // $v0
  int v12; // $s0
  int v14; // [sp+28h] [-188h] BYREF
  int v15; // [sp+2Ch] [-184h]
  int v16; // [sp+30h] [-180h] BYREF
  int v17; // [sp+34h] [-17Ch]
  int v18; // [sp+38h] [-178h] BYREF
  int v19; // [sp+3Ch] [-174h]
  _BYTE v20[64]; // [sp+40h] [-170h] BYREF
  int v21; // [sp+80h] [-130h] BYREF
  int v22; // [sp+84h] [-12Ch]
  int v23; // [sp+88h] [-128h]
  int v24; // [sp+8Ch] [-124h]
  int v25; // [sp+90h] [-120h]
  int v26; // [sp+94h] [-11Ch]
  int v27; // [sp+98h] [-118h]
  int v28; // [sp+9Ch] [-114h]
  _BYTE v29[64]; // [sp+A0h] [-110h] BYREF
  _BYTE v30[128]; // [sp+E0h] [-D0h] BYREF
  char v31[24]; // [sp+160h] [-50h] BYREF
  _BYTE *v32; // [sp+178h] [-38h]
  int Object; // [sp+17Ch] [-34h]
  int Array; // [sp+180h] [-30h]
  const char *v35; // [sp+184h] [-2Ch]
  const char *v36; // [sp+188h] [-28h]
  const char *v37; // [sp+18Ch] [-24h]
  char *v38; // [sp+190h] [-20h]
  const char *v39; // [sp+194h] [-1Ch]
  char *v40; // [sp+198h] [-18h]
  const char *v41; // [sp+19Ch] [-14h]
  const char *v42; // [sp+1A0h] [-10h]
  char *v43; // [sp+1A4h] [-Ch]
  char *v44; // [sp+1A8h] [-8h]

  v14 = 0;
  v15 = 0;
  v16 = 0;
  v17 = 0;
  v18 = 0;
  v19 = 0;
  memset(v20, 0, sizeof(v20));
  v21 = 0;
  v22 = 0;
  v23 = 0;
  v24 = 0;
  v25 = 0;
  v26 = 0;
  v27 = 0;
  v28 = 0;
  memset(v29, 0, sizeof(v29));
  memset(v30, 0, sizeof(v30));
  Object = cJSON_CreateObject();
  strcpy(v31, "/tmp/miniupnpd.leases");
  v0 = nvram_safe_get("upnp_enable_x");
  String = cJSON_CreateString(v0);
  cJSON_AddItemToObject(Object, "enable", String);
  Array = cJSON_CreateArray();
  v2 = fopen(v31, "r");
  if ( v2 )
  {
    v3 = 0;
    v35 = "%[^':']:%[^':']:%[^':']:%[^':']:%*d:%s";
    v36 = "%d";
    v37 = "idx";
    v38 = "proto";
    v39 = "ePort";
    v40 = "ip";
    v41 = "iPort";
    v42 = "desc";
    v43 = "1";
    v44 = "status";
    while ( fgets(v30, 128, v2) )
    {
      if ( v30[0] )
      {
        ++v3;
        v4 = cJSON_CreateObject();
        v32 = v29;
        sscanf(v30, v35, &v14, &v16, &v21, &v18, v29);
        snprintf(v20, 8, v36, v3);
        v5 = cJSON_CreateString(v20);
        cJSON_AddItemToObject(v4, v37, v5);
        v6 = cJSON_CreateString(&v14);
        cJSON_AddItemToObject(v4, v38, v6);
        v7 = cJSON_CreateString(&v16);
        cJSON_AddItemToObject(v4, v39, v7);
        v8 = cJSON_CreateString(&v21);
        cJSON_AddItemToObject(v4, v40, v8);
        v9 = cJSON_CreateString(&v18);
        cJSON_AddItemToObject(v4, v41, v9);
        v10 = cJSON_CreateString(v32);
        cJSON_AddItemToObject(v4, v42, v10);
        v11 = cJSON_CreateString(v43);
        cJSON_AddItemToObject(v4, v44, v11);
        cJSON_AddItemToArray(Array, v4);
      }
      v14 = 0;
      v15 = 0;
      v16 = 0;
      v17 = 0;
      v21 = 0;
      v22 = 0;
      v23 = 0;
      v24 = 0;
      v25 = 0;
      v26 = 0;
      v27 = 0;
      v28 = 0;
      v18 = 0;
      v19 = 0;
      memset(v29, 0, sizeof(v29));
      memset(v30, 0, sizeof(v30));
    }
    fclose(v2);
  }
  cJSON_AddItemToObject(Object, "upnpList", Array);
  v12 = cJSON_Print(Object);
  puts(v12);
  cJSON_Delete(Object);
  free(v12);
  return 1;
}
