/* =====================================================
 *  Path 19
 *  vuln_type = CWE-120
 *  sink_func = memset
 *  source_func = sscanf
 *  Hops:
 *    - memset (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - sub_404258 (arg=0, call_ea=0x4044c4, func_ea=0x404258, label=needs_check)
 *        call: memset(v43, 0, sizeof(v43));
 *    - sscanf (arg=0, call_ea=0x4043e0, func_ea=source, label=source)
 *        call: sscanf(v43, "%*s%s%s%s%*s%s%*s%*s%*s", v45, v46, v47, v44);
 * ===================================================== */


/* Function: sub_404258 @ 0x404258 */
int sub_404258()
{
  int Object; // $s0
  int v1; // $s1
  int v2; // $s3
  int v3; // $v0
  int v4; // $v0
  int v5; // $v0
  int v6; // $v0
  int v7; // $v0
  int v8; // $v0
  int v9; // $v0
  int v10; // $v0
  int v11; // $v0
  int v12; // $v0
  int v13; // $v0
  int v14; // $v0
  int v15; // $v0
  int v16; // $v0
  int v17; // $v0
  int v18; // $v0
  int v19; // $v0
  int v20; // $v0
  int v21; // $v0
  int v22; // $v0
  int v23; // $v0
  int v24; // $v0
  int v25; // $v0
  int v26; // $v0
  int v27; // $v0
  int String; // $v0
  int v29; // $v0
  int v30; // $v0
  int v31; // $v0
  int v32; // $v0
  int v33; // $v0
  int v34; // $v0
  int v35; // $s1
  int v37; // $v0
  int v38; // $v0
  int v39; // $v0
  int v40; // $v0
  int v41; // $s1
  _BYTE v42[128]; // [sp+20h] [-300h] BYREF
  _BYTE v43[512]; // [sp+A0h] [-280h] BYREF
  _DWORD v44[8]; // [sp+2A0h] [-80h] BYREF
  _DWORD v45[8]; // [sp+2C0h] [-60h] BYREF
  _DWORD v46[8]; // [sp+2E0h] [-40h] BYREF
  _DWORD v47[8]; // [sp+300h] [-20h] BYREF

  memset(v42, 0, sizeof(v42));
  memset(v43, 0, sizeof(v43));
  memset(v44, 0, sizeof(v44));
  memset(v45, 0, sizeof(v45));
  memset(v46, 0, sizeof(v46));
  memset(v47, 0, sizeof(v47));
  Object = cJSON_CreateObject();
  if ( isWanConnected() != 1 )
  {
    if ( nvram_get_int("tnt_err_code") == -1 )
      String = cJSON_CreateString("1");
    else
      String = cJSON_CreateString(&word_42F754);
    cJSON_AddItemToObject(Object, "status", String);
    v29 = cJSON_CreateString(&word_42F754);
    cJSON_AddItemToObject(Object, "connectTime", v29);
    v30 = cJSON_CreateString(&word_42F754);
    cJSON_AddItemToObject(Object, "type", v30);
    v31 = cJSON_CreateString(&byte_431360);
    cJSON_AddItemToObject(Object, "warning", v31);
    v32 = cJSON_CreateString(&byte_431360);
    cJSON_AddItemToObject(Object, "ipAddr", v32);
    goto LABEL_48;
  }
  v1 = nvram_get_int("tnt_err_code");
  if ( v1 )
  {
    if ( v1 == -1 )
    {
      v14 = cJSON_CreateString("1");
      cJSON_AddItemToObject(Object, "status", v14);
      v15 = cJSON_CreateString(&word_42F754);
      cJSON_AddItemToObject(Object, "connectTime", v15);
      v16 = cJSON_CreateString(&word_42F754);
      cJSON_AddItemToObject(Object, "type", v16);
    }
    else if ( (unsigned int)(v1 - 1) >= 6 )
    {
      if ( v1 == 99 )
        v25 = cJSON_CreateString("3");
      else
        v25 = cJSON_CreateString(&word_42F754);
      cJSON_AddItemToObject(Object, "status", v25);
      v26 = cJSON_CreateString(&word_42F754);
      cJSON_AddItemToObject(Object, "connectTime", v26);
      v27 = cJSON_CreateString(&word_42F754);
      cJSON_AddItemToObject(Object, "type", v27);
    }
    else
    {
      v17 = cJSON_CreateString(&word_42F5AC);
      cJSON_AddItemToObject(Object, "status", v17);
      v18 = cJSON_CreateString(&word_42F754);
      cJSON_AddItemToObject(Object, "connectTime", v18);
      v19 = cJSON_CreateString(&word_42F754);
      cJSON_AddItemToObject(Object, "type", v19);
      if ( v1 == 1 )
      {
        v20 = cJSON_CreateString("net_id error");
        cJSON_AddItemToObject(Object, "warning", v20);
      }
      else if ( v1 == 2 )
      {
        v21 = cJSON_CreateString("dev_id error");
        cJSON_AddItemToObject(Object, "warning", v21);
      }
      else if ( v1 == 3 )
      {
        v22 = cJSON_CreateString("dev_id exist");
        cJSON_AddItemToObject(Object, "warning", v22);
      }
      else if ( v1 == 4 )
      {
        v23 = cJSON_CreateString("passowrd error");
        cJSON_AddItemToObject(Object, "warning", v23);
      }
      else
      {
        if ( v1 == 5 )
          v24 = cJSON_CreateString("dev_info error");
        else
          v24 = cJSON_CreateString("password bound");
        cJSON_AddItemToObject(Object, "warning", v24);
      }
    }
LABEL_48:
    v33 = nvram_safe_get("tnt_ip_conflict");
    v34 = cJSON_CreateString(v33);
    cJSON_AddItemToObject(Object, "warning", v34);
    v35 = cJSON_Print(Object);
    puts(v35);
    cJSON_Delete(Object);
    free(v35);
    return 1;
  }
  if ( !access("/var/run/tnt.edge_list", 0) )
  {
    v2 = fopen("/var/run/tnt.edge_list", "r");
    if ( v2 )
    {
      do
      {
        if ( !fgets(v43, 512, v2) )
          break;
        sscanf(v43, "%*s%s%s%s%*s%s%*s%*s%*s", v45, v46, v47, v44);
      }
      while ( strcmp(v44, "10.100.100.1") );
      fclose(v2);
      v3 = SLOBYTE(v45[0]);
    }
    else
    {
      v3 = SLOBYTE(v45[0]);
    }
    if ( v3 && LOBYTE(v46[0]) && LOBYTE(v47[0]) )
    {
      snprintf(
        v42,
        128,
        "tinc -n tnt info %s%s%s | grep Reachability 2>/dev/null",
        (const char *)v45,
        (const char *)v46,
        (const char *)v47);
      memset(v43, 0, sizeof(v43));
      getCmdStr(v42, v43, 512);
      if ( strstr(v43, "directly") )
      {
        v4 = cJSON_CreateString("1");
        cJSON_AddItemToObject(Object, "type", v4);
        v5 = 1;
      }
      else if ( strstr(v43, "forwarded") )
      {
        v6 = cJSON_CreateString(&word_42F5AC);
        cJSON_AddItemToObject(Object, "type", v6);
        v5 = 1;
      }
      else
      {
        v7 = cJSON_CreateString(&word_42F754);
        cJSON_AddItemToObject(Object, "type", v7);
        v5 = 0;
      }
      if ( v43[0] )
      {
        if ( v5 )
        {
          if ( !*(_BYTE *)nvram_safe_get("tnt_ip_conflict") )
          {
            v8 = cJSON_CreateString("4");
            cJSON_AddItemToObject(Object, "status", v8);
          }
          if ( *(_BYTE *)nvram_safe_get("tnt_ip_conflict") )
          {
            v9 = cJSON_CreateString("5");
            cJSON_AddItemToObject(Object, "status", v9);
          }
          v10 = nvram_get("tnt_connect_time");
          v11 = cJSON_CreateString(v10);
          cJSON_AddItemToObject(Object, "connectTime", v11);
        }
        else
        {
          v12 = cJSON_CreateString(&word_42F754);
          cJSON_AddItemToObject(Object, "status", v12);
          v13 = cJSON_CreateString(&word_42F754);
          cJSON_AddItemToObject(Object, "connectTime", v13);
        }
        goto LABEL_48;
      }
    }
  }
  v37 = cJSON_CreateString(&word_42F754);
  cJSON_AddItemToObject(Object, "type", v37);
  if ( nvram_get_int("tnt_err_code") == -1 )
    v38 = cJSON_CreateString("1");
  else
    v38 = cJSON_CreateString(&word_42F754);
  cJSON_AddItemToObject(Object, "status", v38);
  v39 = cJSON_CreateString(&word_42F754);
  cJSON_AddItemToObject(Object, "connectTime", v39);
  v40 = cJSON_CreateString(&byte_431360);
  cJSON_AddItemToObject(Object, "warning", v40);
  v41 = cJSON_Print(Object);
  puts(v41);
  cJSON_Delete(Object);
  free(v41);
  return 1;
}
