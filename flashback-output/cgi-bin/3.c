/* =====================================================
 *  Path 3
 *  vuln_type = CWE-78
 *  sink_func = doSystem
 *  source_func = websGetVar
 *  Hops:
 *    - doSystem (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - sub_4263CC (arg=1, call_ea=0x4264f0, func_ea=0x4263cc, label=certain)
 *        call: doSystem("mv %s %s", Var, v44);
 *    - websGetVar (arg=ret, call_ea=0x426440, func_ea=source, label=source)
 *        call: Var = (const char *)websGetVar(a1, "FileName", &byte_431360);
 * ===================================================== */


/* Function: sub_4263CC @ 0x4263CC */
int __fastcall sub_4263CC(int a1)
{
  const char *Var; // $s2
  int v3; // $s1
  int Object; // $s0
  int v5; // $s1
  int String; // $v0
  int v7; // $v0
  unsigned int v8; // $v0
  int v9; // $v0
  int v10; // $v0
  int v11; // $s4
  int v12; // $v0
  int v13; // $s2
  _DWORD *v14; // $v0
  const char *v15; // $v0
  _DWORD *v16; // $v0
  const char *v17; // $v0
  _DWORD *v18; // $s3
  _DWORD *v19; // $v0
  const char *v20; // $v0
  int v21; // $v0
  int v22; // $a1
  int v23; // $a0
  int v24; // $v1
  int v25; // $v0
  int v26; // $v0
  int v27; // $s7
  int v28; // $s5
  int *v29; // $v0
  int *v30; // $v1
  int v31; // $a3
  int v32; // $a2
  int v33; // $a1
  int v34; // $s1
  int v35; // $v0
  int v36; // $s1
  int v37; // $v0
  int v38; // $v0
  int v39; // $v0
  int Number; // $v0
  const char *v41; // $s1
  const char *v43; // $s1
  char v44[128]; // [sp+20h] [-2E4h] BYREF
  char v45[256]; // [sp+A0h] [-264h] BYREF
  _DWORD v46[4]; // [sp+1A0h] [-164h] BYREF
  int v47; // [sp+1B0h] [-154h] BYREF
  int v48; // [sp+1B4h] [-150h]
  int v49; // [sp+1B8h] [-14Ch]
  int v50; // [sp+1BCh] [-148h]
  _DWORD v51[10]; // [sp+1C0h] [-144h] BYREF
  _DWORD v52[16]; // [sp+1E8h] [-11Ch] BYREF
  int v53; // [sp+228h] [-DCh] BYREF
  int v54; // [sp+22Ch] [-D8h]
  int v55; // [sp+234h] [-D0h]
  int v56; // [sp+240h] [-C4h]
  int v57; // [sp+248h] [-BCh]
  int v58; // [sp+24Ch] [-B8h]
  int v59; // [sp+250h] [-B4h]
  int v60; // [sp+254h] [-B0h]
  int v61; // [sp+258h] [-ACh]
  int v62; // [sp+25Ch] [-A8h]
  int v63; // [sp+260h] [-A4h]
  int v64; // [sp+264h] [-A0h]
  _BYTE v65[52]; // [sp+268h] [-9Ch] BYREF
  int v66; // [sp+29Ch] [-68h]

  memset(v44, 0, sizeof(v44));
  Var = (const char *)websGetVar(a1, "FileName", &byte_431360);
  websGetVar(a1, "FullName", &byte_431360);
  v3 = websGetVar(a1, "ContentLength", &word_42F754);
  Object = cJSON_CreateObject();
  v5 = strtol(v3, 0, 10) + 1;
  strcpy(v44, "/tmp/myImage.img");
  doSystem("mv %s %s", Var, v44);
  if ( v5 < 0x8000 )
  {
    String = cJSON_CreateString("MM_FwFileInvalid");
    cJSON_AddItemToObject(Object, "upgradeERR", String);
LABEL_53:
    doSystem("rm -f %s", v44);
    v43 = (const char *)cJSON_Print(Object);
    printf("%s", v43);
    free(v43);
    cJSON_Delete(Object);
    return 0;
  }
  if ( !v44[0] )
  {
    v7 = cJSON_CreateString("MM_fwupload_error");
    cJSON_AddItemToObject(Object, "upgradeERR", v7);
    goto LABEL_53;
  }
  v8 = (unsigned int)get_mtd_size("fullflash") >> 20;
  if ( !v8 )
  {
    v9 = cJSON_CreateString("MM_flashsize_error");
    cJSON_AddItemToObject(Object, "upgradeERR", v9);
    goto LABEL_53;
  }
  if ( (int)(v8 << 20) < v5 )
  {
    v10 = cJSON_CreateString("MM_cloud_fw2flash1");
    cJSON_AddItemToObject(Object, "upgradeERR", v10);
    goto LABEL_53;
  }
  memset(v52, 0, sizeof(v52));
  memset(v46, 0, sizeof(v46));
  v47 = 0;
  v48 = 0;
  v49 = 0;
  v50 = 0;
  v11 = v5;
  v12 = open(v44, 0);
  v13 = v12;
  if ( !v12 )
  {
    v14 = (_DWORD *)_errno_location();
    v15 = (const char *)strerror(*v14);
    sprintf(v45, "Can't open %s: %s\n", v44, v15);
    goto LABEL_42;
  }
  if ( fstat(v12, v65) < 0 )
  {
    close(v13);
    v16 = (_DWORD *)_errno_location();
    v17 = (const char *)strerror(*v16);
    sprintf(v45, "Can't stat %s: %s\n", v44, v17);
    goto LABEL_42;
  }
  v18 = (_DWORD *)mmap(0, v66, 1, 1, v13, 0);
  if ( v18 == (_DWORD *)-1 )
  {
    close(v13);
    v19 = (_DWORD *)_errno_location();
    v20 = (const char *)strerror(*v19);
    sprintf(v45, "Can't mmap %s: %s\n", v44, v20);
    goto LABEL_42;
  }
  v21 = nvram_safe_get("csid_custom");
  strcpy(v46, v21);
  nvram_set_int_temp("only_custom", 0);
  nvram_set_int_temp("flash_custom", 0);
  if ( strstr(v18 + 11, "USERDATABIN") )
  {
    memset(v51, 0, sizeof(v51));
    v22 = v18[15];
    v23 = v18[16];
    v24 = v18[17];
    v47 = v18[14];
    v48 = v22;
    v49 = v23;
    v50 = v24;
    v25 = _bswapsi2(*v18);
    f_write("/tmp/custom.bin", v18 + 19, v25, 0, 0);
    Cal_file_md5("/tmp/custom.bin", v51);
    if ( strcasecmp(v51, v18 + 1) )
    {
LABEL_18:
      close(v13);
      goto LABEL_42;
    }
    nvram_set_int_temp("flash_custom", 1);
    v26 = _bswapsi2(*v18);
    if ( v5 < 0x100000 )
    {
      if ( !strcmp("C8340R", v46) )
      {
        if ( !strstr(&v47, "C8340R") )
          goto LABEL_18;
      }
      else if ( !strcmp(&v47, v46) || strcmp("C8340R", &v47) )
      {
        goto LABEL_18;
      }
      nvram_set_int_temp("only_custom", 1);
      v28 = 2;
      goto LABEL_41;
    }
    v27 = v26 + 76;
    v28 = 3;
  }
  else
  {
    v27 = 0;
    v28 = 1;
  }
  v29 = (_DWORD *)((char *)v18 + v27);
  v30 = &v53;
  do
  {
    v31 = v29[1];
    v32 = v29[2];
    v33 = v29[3];
    *v30 = *v29;
    v30[1] = v31;
    v30[2] = v32;
    v30[3] = v33;
    v29 += 4;
    v30 += 4;
  }
  while ( v29 != (_DWORD *)((char *)v18 + v27 + 64) );
  if ( _bswapsi2(v53) != 654645590 )
  {
    munmap(v18, v5);
    close(v13);
    sprintf(v45, "Bad Magic Number: \"%s\" is no valid image\n", v44);
    goto LABEL_42;
  }
  v34 = _bswapsi2(v54);
  v54 = 0;
  if ( v34 != crc32_sp(0, &v53, 64) )
  {
    munmap(v18, v11);
    close(v13);
    sprintf(v45, "*** Warning: \"%s\" has bad header checksum!\n", v44);
    goto LABEL_42;
  }
  v35 = _bswapsi2(v55);
  v36 = crc32_sp(0, (char *)v18 + v27 + 64, v35);
  if ( v36 != _bswapsi2(v56) )
  {
    munmap(v18, v11);
    close(v13);
    sprintf(v45, "*** Warning: \"%s\" has corrupted data!\n", v44);
    goto LABEL_42;
  }
  v52[0] = v57;
  v52[1] = v58;
  v52[2] = v59;
  v52[3] = v60;
  v52[4] = v61;
  v52[5] = v62;
  v52[6] = v63;
  v52[7] = v64;
  if ( !strstr(v52, "C8340R") )
  {
    munmap(v18, v11);
    close(v13);
    strcpy(v45, "MM_cloud_fw2flash2");
LABEL_42:
    if ( strstr(v45, "product_name_error") )
    {
      v37 = cJSON_CreateString("MM_cloud_fw2flash2");
      cJSON_AddItemToObject(Object, "upgradeERR", v37);
    }
    else
    {
      if ( strstr(v45, "product_svn_error") )
        v38 = cJSON_CreateString("MM_cloud_fw2flash3");
      else
        v38 = cJSON_CreateString("MM_cloud_fw2flash1");
      cJSON_AddItemToObject(Object, "upgradeERR", v38);
    }
    goto LABEL_53;
  }
  if ( v28 == 3 )
    f_write("/tmp/linux.trx", (char *)v18 + v27, v11 - v27, 0, 0);
LABEL_41:
  munmap(v18, v11);
  close(v13);
  if ( v28 == 1 )
  {
    doSystem("mv %s %s", v44, "/tmp/linux.trx");
    strcpy(v44, "/tmp/linux.trx");
  }
  else if ( v28 == 3 )
  {
    doSystem("rm -f %s", v44);
  }
  v39 = cJSON_CreateString("1");
  cJSON_AddItemToObject(Object, "upgradeStatus", v39);
  Number = cJSON_CreateNumber();
  cJSON_AddItemToObject(Object, "wtime", Number);
  v41 = (const char *)cJSON_Print(Object);
  printf("%s", v41);
  free(v41);
  cJSON_Delete(Object);
  return 0;
}
