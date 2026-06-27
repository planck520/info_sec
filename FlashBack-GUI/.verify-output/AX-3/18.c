/* =====================================================
 *  Path 18
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - fromSetIpMacBind (arg=1, call_ea=0x53b14, func_ea=0x53974, label=needs_check)
 *        call: strcpy(s, v8);
 *    - websGetVar (arg=ret, call_ea=0x539ec, func_ea=source, label=source)
 *        call: Var = websGetVar(wp, "list", &byte_794DF);
 * ===================================================== */


/* Function: fromSetIpMacBind @ 0x53974 */
void __fastcall fromSetIpMacBind(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r5
  unsigned int v5; // r0
  int i; // r4
  char *v7; // r0
  const char *v8; // r1
  int v9; // r3
  int v10; // r5
  int v11; // r2
  int v12; // r2
  int old_static_num; // [sp+8h] [bp-448h]
  char *nptr; // [sp+Ch] [bp-444h]
  int v15; // [sp+10h] [bp-440h]
  char v16[32]; // [sp+28h] [bp-428h] BYREF
  char v17[32]; // [sp+48h] [bp-408h] BYREF
  char mib_name[64]; // [sp+68h] [bp-3E8h] BYREF
  char v19[64]; // [sp+A8h] [bp-3A8h] BYREF
  char v20[64]; // [sp+E8h] [bp-368h] BYREF
  char mib_value[128]; // [sp+128h] [bp-328h] BYREF
  char s[128]; // [sp+1A8h] [bp-2A8h] BYREF
  char ret_buf[256]; // [sp+228h] [bp-228h] BYREF
  char param_str[256]; // [sp+328h] [bp-128h] BYREF

  memset(ret_buf, 0, sizeof(ret_buf));
  memset(mib_name, 0, sizeof(mib_name));
  memset(mib_value, 0, sizeof(mib_value));
  nptr = websGetVar(wp, "bindnum", "0");
  Var = websGetVar(wp, "list", &byte_794DF);
  GetValue("dhcps.Staticnum", mib_value);
  v15 = atoi(mib_value);
  v5 = atoi(nptr);
  old_static_num = v5;
  if ( v5 > 0x20 )
  {
    printf("staic ip number over %d\n", 32);
    goto LABEL_30;
  }
  for ( i = 1; ; ++i )
  {
    v9 = (int)Var;
    if ( Var )
      v9 = 1;
    if ( i > old_static_num )
      v9 = 0;
    if ( !v9 )
      break;
    memset(s, 0, sizeof(s));
    memset(v19, 0, sizeof(v19));
    memset(param_str, 0, 0x80u);
    memset(v16, 0, sizeof(v16));
    memset(v17, 0, sizeof(v17));
    memset(v20, 0, sizeof(v20));
    v7 = strchr(Var, 10);
    if ( v7 )
    {
      v8 = Var;
      Var = v7 + 1;
      *v7 = 0;
      strcpy(s, v8);
    }
    else
    {
      strcpy(s, Var);
    }
    if ( s[0] == 13 )
    {
      if ( _isoc99_sscanf(&s[1], "%17[0-9a-fA-F:]\r%s", v16, v17) != 2 )
        goto LABEL_20;
      strcpy(v20, &byte_794DF);
    }
    else if ( _isoc99_sscanf(s, "%[^\r]\r%[0-9a-fA-F:]\r%s", v20, v16, v17) != 3 )
    {
LABEL_20:
      v5 = puts("get ip and mac error!");
      v9 = 1;
      break;
    }
    printf("%s %d# dev_name=%s,mac_addr=%s,ip_addr=%s\n", "set_mac_bind_list", 430, v20, v16, v17);
    sprintf(v19, "dhcps.Staticip%d", i);
    sprintf(param_str, "%s;%s;0", v17, v16);
    v5 = SetValue(v19, param_str);
    if ( v20[0] )
    {
      memset(v19, 0, sizeof(v19));
      memset(param_str, 0, 0x80u);
      v5 = set_device_name(v20, v16);
    }
  }
  v10 = old_static_num + 1;
  if ( i == old_static_num + 1 )
  {
    if ( !v9 )
    {
      puts("set static num sucess!");
      v5 = SetValue("dhcps.Staticnum", nptr);
      while ( v10 <= v15 )
      {
        memset(mib_value, 0, sizeof(mib_value));
        sprintf(mib_name, "dhcps.Staticip%d", v10);
        GetValue(mib_name, mib_value);
        v11 = v10++;
        sprintf(mib_name, "dhcps.Staticip%d", v11);
        v5 = SetValue(mib_name, &byte_794DF);
      }
      goto LABEL_27;
    }
LABEL_30:
    v12 = 1;
    goto Finish;
  }
  if ( v9 )
    goto LABEL_30;
LABEL_27:
  if ( CommitCfm(v5) )
  {
    memset(param_str, 0, sizeof(param_str));
    sprintf(param_str, "op=%d,index=1", 6);
    send_msg_to_netctrl(3, param_str);
  }
  v12 = 0;
Finish:
  sprintf(ret_buf, "{\"errCode\":%d}", v12);
  websTransfer(wp, ret_buf);
}
