/* =====================================================
 *  Path 9
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - sub_424228 (arg=1, call_ea=0x424664, func_ea=0x424228, label=needs_check)
 *        call: strcpy(v26, v8);
 *    - websGetVar (arg=ret, call_ea=0x4244d8, func_ea=source, label=source)
 *        call: v8 = (_BYTE *)websGetVar(Object, "http_host", &byte_431360);
 * ===================================================== */


/* Function: sub_424228 @ 0x424228 */
int __fastcall sub_424228(int a1)
{
  int Var; // $s5
  int v3; // $a0
  int String; // $v0
  int v5; // $s2
  const char *v6; // $s1
  int v7; // $s4
  _BYTE *v8; // $s2
  int v9; // $s0
  int v10; // $s3
  int v11; // $s5
  int v12; // $v0
  int v13; // $v0
  int v14; // $s2
  BOOL v15; // $s2
  int v16; // $s3
  int v17; // $s2
  int v18; // $v0
  const char *v19; // $s0
  char v21[128]; // [sp+28h] [-17B0h] BYREF
  _BYTE v22[4096]; // [sp+A8h] [-1730h] BYREF
  _BYTE v23[1024]; // [sp+10A8h] [-730h] BYREF
  _BYTE v24[128]; // [sp+14A8h] [-330h] BYREF
  _BYTE v25[256]; // [sp+1528h] [-2B0h] BYREF
  char v26[256]; // [sp+1628h] [-1B0h] BYREF
  _DWORD v27[8]; // [sp+1728h] [-B0h] BYREF
  char v28; // [sp+1748h] [-90h]
  _DWORD v29[8]; // [sp+174Ch] [-8Ch] BYREF
  char v30; // [sp+176Ch] [-6Ch]
  _DWORD v31[8]; // [sp+1770h] [-68h] BYREF
  _BYTE v32[64]; // [sp+1790h] [-48h] BYREF
  _BYTE *v33; // [sp+17D0h] [-8h]
  int Object; // [sp+17D4h] [-4h]

  memset(v21, 0, sizeof(v21));
  memset(v22, 0, sizeof(v22));
  memset(v23, 0, sizeof(v23));
  memset(v24, 0, sizeof(v24));
  memset(v25, 0, sizeof(v25));
  memset(v26, 0, sizeof(v26));
  memset(v27, 0, sizeof(v27));
  v28 = 0;
  memset(v29, 0, sizeof(v29));
  v30 = 0;
  memset(v31, 0, sizeof(v31));
  memset(v32, 0, sizeof(v32));
  Var = websGetVar(a1, "loginAuthUrl", &byte_431360);
  Object = cJSON_CreateObject();
  v3 = 0;
  v33 = v25;
  while ( 1 )
  {
    v5 = v3 + 1;
    if ( getNthValueSafe(v3, Var, "&", v23, 1024) == -1 )
      break;
    if ( getNthValueSafe(0, v23, "=", v24, 128) != -1 && getNthValueSafe(1, v23, "=", v33, 256) != -1 )
    {
      String = cJSON_CreateString(v33);
      cJSON_AddItemToObject(Object, v24, String);
    }
    v3 = v5;
  }
  v6 = (const char *)websGetVar(Object, "username", &byte_431360);
  v7 = websGetVar(Object, "password", &byte_431360);
  v8 = (_BYTE *)websGetVar(Object, "http_host", &byte_431360);
  v9 = websGetVar(Object, "flag", &word_42F754);
  v10 = nvram_get_int("wizard_flag");
  if ( v10 )
  {
    if ( ((v11 = nvram_safe_get("opmode_custom"), !strcmp(v11, "gw")) || !strcmp(v11, "wisp")) && isWanConnected()
      || !strcmp(v11, "rpt") && get_apcli_connected() == 1
      || !strcmp(v11, "br") && nvram_get_int("dl_status_lan") == 1 )
    {
      v10 = 0;
    }
  }
  urldecode(v7, v32);
  v12 = nvram_safe_get("http_username");
  strcpy(v27, v12);
  v13 = nvram_safe_get("http_passwd");
  strcpy(v29, v13);
  if ( *v8 )
    strcpy(v26, v8);
  else
    strcpy(v26, v31);
  v14 = strcmp(v6, v27);
  v15 = strcmp(v32, v29) || v14 != 0;
  if ( v9 )
    strcpy(v6, v27);
  if ( !strcmp(v6, v27) && !strcmp(v32, v29) )
  {
    if ( !strcmp(v9, "ie8") )
    {
      strcpy(v21, "wan_ie.html");
    }
    else if ( atoi(v9) == 1 )
    {
      if ( v10 )
        strcpy(v21, "phone/wizard.html");
      else
        strcpy(v21, "phone/home.html");
    }
    else if ( v10 )
    {
      strcpy(v21, "wizard.html");
    }
    else
    {
      strcpy(v21, "home.html");
    }
    nvram_set_int_temp("cloudupg_checktype", 1);
    doSystem("lktos_reload %s", "cloudupdate_check 2>/dev/null");
    v16 = 1;
  }
  else
  {
    if ( !strcmp(v9, "ie8") )
    {
      strcpy(v21, "login_ie.html");
    }
    else if ( atoi(v9) == 1 )
    {
      strcpy(v21, "phone/login.html");
    }
    else
    {
      strcpy(v21, "login.html");
    }
    v16 = 0;
    if ( v15 )
    {
      system("echo ''> /tmp/login_flag");
      v16 = 0;
    }
  }
  snprintf(v22, 4096, "{\"httpStatus\":\"%s\",\"host\":\"%s\"", "302", v26);
  v17 = strlen(v22);
  if ( atoi(v9) == 1 )
    snprintf(
      &v22[v17],
      4096 - v17,
      ",\"redirectURL\":\"http://%s/formLoginAuth.htm?authCode=%d&userName=%s&goURL=%s&action=login&flag=1\"}",
      v26,
      v16,
      v6,
      v21);
  else
    snprintf(
      &v22[v17],
      4096 - v17,
      ",\"redirectURL\":\"http://%s/formLoginAuth.htm?authCode=%d&userName=%s&goURL=%s&action=login\"}",
      v26,
      v16,
      v6,
      v21);
  v18 = cJSON_Parse(v22);
  v19 = (const char *)websGetVar(v18, "redirectURL", &byte_431360);
  puts("HTTP/1.1 302 Redirect to page");
  puts("Content-type: text/plain");
  puts("Connection: Keep-Alive\nPragma: no-cache\nCache-Control: no-cache");
  printf("Location: %s\n\n", v19);
  printf("protal page");
  return 0;
}
