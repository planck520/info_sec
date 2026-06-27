/* =====================================================
 *  Path 2
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - set_macfilter_rules_by_one (arg=1, call_ea=0x4180c, func_ea=0x41640, label=needs_check)
 *        call: strcpy(&cgi_debug[32], source_rule);
 *    - formSetMacFilterCfg (arg=1, call_ea=0x44828, func_ea=0x442b0, label=needs_check)
 *        call: set_macfilter_rules_by_one(Var, v4, v10, &v41[v9]);
 *    - websGetVar (arg=ret, call_ea=0x443c8, func_ea=source, label=source)
 *        call: v4 = websGetVar(wp, "deviceList", &byte_794DF);
 * ===================================================== */


/* Function: set_macfilter_rules_by_one @ 0x41640 */
// local variable allocation has failed, the output may be wrong!
FUNC_RETVAL __fastcall set_macfilter_rules_by_one(
        const char *const filter_mode,
        char *source_rule,
        const int index,
        char *mac_add)
{
  char *v7; // r0
  const char *v8; // r11
  _DWORD *v9; // r2
  int v10; // r1
  bool v11; // zf
  char cgi_debug_0[16]; // [sp+20h] [bp-1D8h] BYREF
  char mib_name[128]; // [sp+30h] [bp-1C8h] BYREF
  char mib_value[128]; // [sp+B0h] [bp-148h] BYREF
  _BYTE cgi_debug[160]; // [sp+130h] [bp-C8h] OVERLAPPED BYREF

  memset(mib_name, 0, sizeof(mib_name));
  memset(mib_value, 0, sizeof(mib_value));
  memset(cgi_debug, 0, 0x10u);
  if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
    printf(
      "%s[%s:%s:%d] %sset macfilter rules by one, source_rule == %s, index == %d\n\x1B[0m",
      "\x1B[0;33m",
      "cgi",
      "set_macfilter_rules_by_one",
      773,
      "\x1B[0;32m",
      source_rule,
      index);
  memset(cgi_debug, 0, sizeof(cgi_debug));
  v7 = strchr(source_rule, 13);
  if ( v7 )
  {
    *v7 = 0;
    v8 = v7 + 1;
    memset(cgi_debug_0, 0, sizeof(cgi_debug_0));
    if ( GetValue("cgi_debug", cgi_debug_0) && !strcmp("on", cgi_debug_0) )
      printf(
        "%s[%s:%s:%d] %sparase rule: name == %s, mac == %s\n\x1B[0m",
        "\x1B[0;33m",
        "cgi",
        "parse_macfilter_rule",
        965,
        "\x1B[0;32m",
        source_rule,
        v8);
    strcpy(&cgi_debug[32], source_rule);
    strcpy(cgi_debug, v8);
  }
  else
  {
    printf(
      "%s[%s:%s:%d] %ssource_rule error: %s!\n\x1B[0m",
      "\x1B[0;33m",
      "cgi",
      "parse_macfilter_rule",
      961,
      "\x1B[0;31m",
      source_rule);
  }
  memset(cgi_debug_0, 0, sizeof(cgi_debug_0));
  if ( GetValue("cgi_debug", cgi_debug_0) && !strcmp("on", cgi_debug_0) )
    printf(
      "%s[%s:%s:%d] %sget rule%d: name == %s, mac == %s\n\x1B[0m",
      "\x1B[0;33m",
      "cgi",
      "set_macfilter_rules_by_one",
      777,
      "\x1B[0;32m",
      index,
      &cgi_debug[32],
      cgi_debug);
  v9 = cgi_debug;
  do
  {
    mac_add += 8;
    v10 = v9[1];
    v11 = v9 + 2 == (_DWORD *)&cgi_debug[32];
    *((_DWORD *)mac_add - 2) = *v9;
    *((_DWORD *)mac_add - 1) = v10;
    v9 += 2;
  }
  while ( !v11 );
  snprintf(mib_name, 0x80u, "macfilter.%s.list%d", filter_mode, index);
  snprintf(mib_value, 0x80u, "%s", cgi_debug);
  memset(cgi_debug_0, 0, sizeof(cgi_debug_0));
  if ( GetValue("cgi_debug", cgi_debug_0) && !strcmp("on", cgi_debug_0) )
    printf(
      "%s[%s:%s:%d] %sset rule: %s == %s\n\x1B[0m",
      "\x1B[0;33m",
      "cgi",
      "set_macfilter_rules_by_one",
      782,
      "\x1B[0;32m",
      mib_name,
      mib_value);
  SetValue(mib_name, mib_value);
  if ( cgi_debug[32] )
    set_device_name(&cgi_debug[32], cgi_debug);
  return 0;
}


/* Function: formSetMacFilterCfg @ 0x442B0 */
// local variable allocation has failed, the output may be wrong!
void __fastcall formSetMacFilterCfg(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r6
  char_t *v4; // r8
  int i; // r7
  int j; // r7
  int k; // r11
  char *v8; // r0
  int v9; // r3
  int v10; // r2
  int v11; // r10
  size_t v12; // r0
  int v13; // r2
  int v14; // r4
  int m; // r7
  int v16; // r8
  int v17; // r4
  int v18; // r11
  size_t v19; // r0
  int v20; // r2
  FUNC_RETVAL v21; // r0
  int mibname; // r0
  int v23; // r0
  int v24; // [sp+0h] [bp-1B78h]
  int v25; // [sp+0h] [bp-1B78h]
  int v26; // [sp+0h] [bp-1B78h]
  FUNC_RETVAL c; // [sp+14h] [bp-1B64h]
  int macfilter_rule; // [sp+1Ch] [bp-1B5Ch]
  char *format; // [sp+20h] [bp-1B58h]
  char wifi_24g_enable[32]; // [sp+30h] [bp-1B48h] BYREF
  char wifi_5g_enable[32]; // [sp+50h] [bp-1B28h] BYREF
  char ifname_24g[32]; // [sp+70h] [bp-1B08h] BYREF
  char ifname_5g[32]; // [sp+90h] [bp-1AE8h] BYREF
  char v35[32]; // [sp+B0h] [bp-1AC8h] BYREF
  char s[128]; // [sp+D0h] [bp-1AA8h] BYREF
  char v37[128]; // [sp+150h] [bp-1A28h] BYREF
  char ret_buf[256]; // [sp+1D0h] [bp-19A8h] BYREF
  char mib_name[256]; // [sp+2D0h] [bp-18A8h] BYREF
  char msg_info[256]; // [sp+3D0h] [bp-17A8h] BYREF
  char v41[960]; // [sp+4D0h] [bp-16A8h] BYREF
  _BYTE cgi_debug[4800]; // [sp+890h] [bp-12E8h] OVERLAPPED BYREF

  memset(wifi_24g_enable, 0, sizeof(wifi_24g_enable));
  memset(wifi_5g_enable, 0, sizeof(wifi_5g_enable));
  memset(ifname_24g, 0, sizeof(ifname_24g));
  memset(ifname_5g, 0, sizeof(ifname_5g));
  memset(ret_buf, 0, sizeof(ret_buf));
  memset(mib_name, 0, sizeof(mib_name));
  memset(msg_info, 0, sizeof(msg_info));
  Var = websGetVar(wp, "macFilterType", &byte_794DF);
  c = set_macfilter_mode(Var);
  if ( c )
  {
    printf(
      "%s[%s:%s:%d] %sset mac filter mode error!\n\x1B[0m",
      "\x1B[0;33m",
      "cgi",
      "formSetMacFilterCfg",
      489,
      "\x1B[0;31m");
finished_0:
    snprintf(ret_buf, 0x100u, "{\"errCode\":%d}", c);
    goto LABEL_83;
  }
  v4 = websGetVar(wp, "deviceList", &byte_794DF);
  memset(cgi_debug, 0, sizeof(cgi_debug));
  memset(v41, 0, 0x10u);
  if ( GetValue("cgi_debug", v41) && !strcmp("on", v41) )
    printf("%s[%s:%s:%d] %sset macfilter rules\n\x1B[0m", "\x1B[0;33m", "cgi", "set_macfilter_rules", 689, "\x1B[0;32m");
  if ( !strcmp(Var, "white") )
  {
    memset(cgi_debug, 0, sizeof(cgi_debug));
    macfilter_rule = get_macfilter_rule(Var, (dev_info *const)cgi_debug);
  }
  else
  {
    macfilter_rule = 0;
  }
  memset(v41, 0, 0x80u);
  memset(v37, 0, 0x10u);
  if ( GetValue("cgi_debug", v37) && !strcmp("on", v37) )
    printf(
      "%s[%s:%s:%d] %sunset mac filter rules!\n\x1B[0m",
      "\x1B[0;33m",
      "cgi",
      "unset_macfilter_rules",
      851,
      "\x1B[0;32m");
  snprintf(v41, 0x80u, "macfilter.%s.id", Var);
  UnSetValue(v41);
  memset(v37, 0, 0x10u);
  if ( GetValue("cgi_debug", v37) && !strcmp("on", v37) )
    printf("%s[%s:%s:%d] %sunset %s\n\x1B[0m", "\x1B[0;33m", "cgi", "unset_macfilter_rules", 855, "\x1B[0;32m", v41);
  for ( i = 1; i != 31; ++i )
  {
    v24 = i;
    snprintf(v41, 0x80u, "macfilter.%s.list%d", Var, v24);
    UnSetValue(v41);
  }
  if ( !strcmp(Var, "white") )
  {
    snprintf(v41, 0x80u, "deleted.macfilter.%s.id", Var);
    UnSetValue(v41);
    memset(v37, 0, 0x10u);
    if ( GetValue("cgi_debug", v37) && !strcmp("on", v37) )
      printf("%s[%s:%s:%d] %sunset %s\n\x1B[0m", "\x1B[0;33m", "cgi", "unset_macfilter_rules", 873, "\x1B[0;32m", v41);
    for ( j = 1; j != 31; ++j )
    {
      v25 = j;
      snprintf(v41, 0x80u, "deleted.macfilter.%s.list%d", Var, v25);
      UnSetValue(v41);
    }
  }
  else
  {
    memset(v37, 0, 0x10u);
    if ( GetValue("cgi_debug", v37) && !strcmp("on", v37) )
      printf(
        "%s[%s:%s:%d] %srule list is NULL!\n\x1B[0m",
        "\x1B[0;33m",
        "cgi",
        "unset_macfilter_rules",
        867,
        "\x1B[0;32m");
  }
  if ( *v4 )
  {
    for ( k = 1; ; ++k )
    {
      v8 = strchr(v4, 10);
      v9 = 32 * k;
      if ( !v8 )
        break;
      format = v8 + 1;
      v10 = k;
      *v8 = 0;
      set_macfilter_rules_by_one(Var, v4, v10, &v41[v9]);
      v4 = format;
    }
    set_macfilter_rules_by_one(Var, v4, k, &v41[v9]);
    memset(s, 0, sizeof(s));
    memset(v37, 0, sizeof(v37));
    memset(v35, 0, 0x10u);
    if ( GetValue("cgi_debug", v35) && !strcmp("on", v35) )
      printf(
        "%s[%s:%s:%d] %sfilter_mode == %s, count == %d\n\x1B[0m",
        "\x1B[0;33m",
        "cgi",
        "set_macfilter_list_id",
        997,
        "\x1B[0;32m",
        Var,
        k);
    v11 = 1;
    snprintf(s, 0x80u, "macfilter.%s.id", Var);
    do
    {
      v12 = strlen(v37);
      v13 = v11++;
      sprintf(&v37[v12], "%d,", v13);
    }
    while ( k >= v11 );
    v37[strlen(v37) - 1] = 0;
    memset(v35, 0, 0x10u);
    if ( GetValue("cgi_debug", v35) && !strcmp("on", v35) )
      printf(
        "%s[%s:%s:%d] %sset %s == %s\n\x1B[0m",
        "\x1B[0;33m",
        "cgi",
        "set_macfilter_list_id",
        1009,
        "\x1B[0;32m",
        s,
        v37);
    SetValue(s, v37);
    if ( !strcmp(Var, "white") )
    {
      v14 = 1;
      for ( m = 0; m < macfilter_rule; ++m )
      {
        v16 = 0;
        while ( strcmp(&cgi_debug[160 * m], &v41[32 * v16]) )
        {
          if ( k < ++v16 )
            goto LABEL_48;
        }
        if ( k < v16 )
        {
LABEL_48:
          memset(s, 0, sizeof(s));
          memset(v37, 0, sizeof(v37));
          strcpy(v35, &cgi_debug[160 * m]);
          v26 = v14++;
          snprintf(s, 0x80u, "deleted.macfilter.%s.list%d", Var, v26);
          snprintf(v37, 0x80u, "%s", v35);
          printf("----%s-----%d---set rule: %s == %s\n", "set_macfilter_whiterules_by_one", 822, s, v37);
          SetValue(s, v37);
          continue;
        }
      }
      if ( v14 != 1 )
      {
        memset(s, 0, sizeof(s));
        v17 = v14 - 1;
        memset(v37, 0, sizeof(v37));
        memset(v35, 0, 0x10u);
        if ( GetValue("cgi_debug", v35) && !strcmp("on", v35) )
          printf(
            "%s[%s:%s:%d] %sfilter_mode == %s, count == %d\n\x1B[0m",
            "\x1B[0;33m",
            "cgi",
            "set_macfilter_deletedlist_id",
            1040,
            "\x1B[0;32m",
            Var,
            v17);
        v18 = 1;
        snprintf(s, 0x80u, "deleted.macfilter.%s.id", Var);
        do
        {
          v19 = strlen(v37);
          v20 = v18++;
          sprintf(&v37[v19], "%d,", v20);
        }
        while ( v17 >= v18 );
        v37[strlen(v37) - 1] = 0;
        memset(v35, 0, 0x10u);
        if ( GetValue("cgi_debug", v35) && !strcmp("on", v35) )
          printf(
            "%s[%s:%s:%d] %sset %s == %s\n\x1B[0m",
            "\x1B[0;33m",
            "cgi",
            "set_macfilter_deletedlist_id",
            1052,
            "\x1B[0;32m",
            s,
            v37);
        SetValue(s, v37);
      }
    }
    else
    {
      memset(v37, 0, 0x10u);
      if ( GetValue("cgi_debug", v37) && !strcmp("on", v37) )
        printf(
          "%s[%s:%s:%d] %srule list is NULL!\n\x1B[0m",
          "\x1B[0;33m",
          "cgi",
          "set_macfilter_rules",
          724,
          "\x1B[0;32m");
    }
  }
  else
  {
    memset(v41, (unsigned __int8)*v4, 0x10u);
    if ( GetValue("cgi_debug", v41) && !strcmp("on", v41) )
      printf(
        "%s[%s:%s:%d] %srule list is NULL!\n\x1B[0m",
        "\x1B[0;33m",
        "cgi",
        "set_macfilter_rules",
        705,
        "\x1B[0;32m");
  }
  update_mac_filter_enable_flag();
  v21 = reload_macfilter_rules_to_wireless(Var);
  if ( CommitCfm(v21) )
  {
    send_msg_to_netctrl(9, "op=5");
    wifi_get_mib_radio(2, ifname_24g);
    wifi_get_mib_radio(5, ifname_5g);
    mibname = wifi_get_mibname(ifname_24g, "enable", mib_name);
    GetValue(mibname, wifi_24g_enable);
    v23 = wifi_get_mibname(ifname_5g, "enable", mib_name);
    GetValue(v23, wifi_5g_enable);
    if ( !strcmp("1", wifi_24g_enable) )
    {
      if ( !strcmp("1", wifi_5g_enable) )
      {
        memset(cgi_debug, 0, 0x10u);
        if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
          printf(
            "%s[%s:%s:%d] %s2.4G&5G is enabled, sending msg to 2.4G&5G wifi refresh!\n\x1B[0m",
            "\x1B[0;33m",
            "cgi",
            "formSetMacFilterCfg",
            521,
            "\x1B[0;32m");
        snprintf(msg_info, 0x100u, "op=%d,wl_rate=%d", 12, 7);
      }
      else
      {
        memset(cgi_debug, 0, 0x10u);
        if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
          printf(
            "%s[%s:%s:%d] %s2.4G is enabled, sending msg to 2.4G wifi refresh!\n\x1B[0m",
            "\x1B[0;33m",
            "cgi",
            "formSetMacFilterCfg",
            527,
            "\x1B[0;32m");
        snprintf(msg_info, 0x100u, "op=%d,wl_rate=%d", 12, 2);
      }
    }
    else
    {
      if ( strcmp("1", wifi_5g_enable) )
        goto finished_0;
      memset(cgi_debug, 0, 0x10u);
      if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
        printf(
          "%s[%s:%s:%d] %s5G is enabled, sending msg to 5G wifi refresh!\n\x1B[0m",
          "\x1B[0;33m",
          "cgi",
          "formSetMacFilterCfg",
          533,
          "\x1B[0;32m");
      snprintf(msg_info, 0x100u, "op=%d,wl_rate=%d", 12, 5);
    }
    send_msg_to_netctrl(19, msg_info);
    goto finished_0;
  }
  printf("%s[%s:%s:%d] %scfm commit error!\n\x1B[0m", "\x1B[0;33m", "cgi", "formSetMacFilterCfg", 508, "\x1B[0;31m");
  snprintf(ret_buf, 0x100u, "{\"errCode\":%d}", 1);
LABEL_83:
  websTransfer(wp, ret_buf);
}
