/* =====================================================
 *  Path 42
 *  vuln_type = CWE-120
 *  sink_func = sprintf
 *  source_func = websGetVar
 *  Hops:
 *    - sprintf (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - set_device_name (arg=2, call_ea=0x4158c, func_ea=0x41428, label=needs_check)
 *        call: sprintf(mib_vlaue, "%s\t1", dev_name);
 *    - formAddMacfilterRule (arg=0, call_ea=0x41c88, func_ea=0x41a40, label=needs_check)
 *        call: if ( set_device_name(v4, Var) )
 *    - websGetVar (arg=ret, call_ea=0x41b3c, func_ea=source, label=source)
 *        call: v4 = websGetVar(wp, "devName", &byte_794DF);
 * ===================================================== */


/* Function: set_device_name @ 0x41428 */
FUNC_RETVAL __fastcall set_device_name(const char *const dev_name, const char *const dev_mac)
{
  bool v4; // zf
  char cgi_debug[16]; // [sp+10h] [bp-30h] BYREF
  char mac_addr[32]; // [sp+20h] [bp-20h] BYREF
  char mib_name[128]; // [sp+40h] [bp+0h] BYREF
  char mib_vlaue[256]; // [sp+C0h] [bp+80h] BYREF

  memset(mib_name, 0, sizeof(mib_name));
  memset(mib_vlaue, 0, sizeof(mib_vlaue));
  memset(mac_addr, 0, sizeof(mac_addr));
  v4 = dev_mac == 0;
  if ( dev_mac )
    v4 = dev_name == 0;
  if ( v4 )
  {
    printf(
      "%s[%s:%s:%d] %sparameter error: dev_name or dev_mac is NULL!\n\x1B[0m",
      "\x1B[0;33m",
      "cgi",
      "set_device_name",
      1742,
      "\x1B[0;31m");
    return 2;
  }
  else
  {
    lower_mac(dev_mac, mac_addr);
    if ( set_mac_info(mac_addr, dev_name) )
    {
      printf(
        "%s[%s:%s:%d] %sdevice name setted failed![ %s : %s ]\n\x1B[0m",
        "\x1B[0;33m",
        "cgi",
        "set_device_name",
        1758,
        "\x1B[0;31m",
        dev_name,
        dev_mac);
      return 1;
    }
    else
    {
      memset(cgi_debug, 0, sizeof(cgi_debug));
      if ( GetValue("cgi_debug", cgi_debug) )
      {
        if ( !strcmp("on", cgi_debug) )
          printf(
            "%s[%s:%s:%d] %sset device name %s == %s\n\x1B[0m",
            "\x1B[0;33m",
            "cgi",
            "set_device_name",
            1750,
            "\x1B[0;32m",
            mac_addr,
            dev_name);
      }
      sprintf(mib_name, "client.devicename%s", mac_addr);
      sprintf(mib_vlaue, "%s\t1", dev_name);
      SetValue(mib_name, mib_vlaue);
      return 0;
    }
  }
}


/* Function: formAddMacfilterRule @ 0x41A40 */
// local variable allocation has failed, the output may be wrong!
void __fastcall formAddMacfilterRule(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r11
  char_t *v4; // r6
  _BOOL4 v5; // r3
  size_t v6; // r0
  int v7; // r2
  int v8; // r7
  int v9; // r7
  int v10; // r6
  FUNC_RETVAL v12; // r0
  int mibname; // r0
  int v14; // r0
  int i; // [sp+10h] [bp-568h]
  int id_list; // [sp+1Ch] [bp-55Ch]
  char v18[16]; // [sp+48h] [bp-530h] BYREF
  char mac_filter_mode[32]; // [sp+58h] [bp-520h] BYREF
  char wifi_24g_enable[32]; // [sp+78h] [bp-500h] BYREF
  char wifi_5g_enable[32]; // [sp+98h] [bp-4E0h] BYREF
  char ifname_24g[32]; // [sp+B8h] [bp-4C0h] BYREF
  char ifname_5g[32]; // [sp+D8h] [bp-4A0h] BYREF
  char v24[32]; // [sp+F8h] [bp-480h] BYREF
  char v25[64]; // [sp+118h] [bp-460h] BYREF
  int s[30]; // [sp+158h] [bp-420h] BYREF
  char ret_buf[128]; // [sp+1D0h] [bp-3A8h] BYREF
  int v28[32]; // [sp+250h] [bp-328h] BYREF
  char cgi_debug[128]; // [sp+2D0h] [bp-2A8h] OVERLAPPED BYREF
  char mib_name[256]; // [sp+350h] [bp-228h] BYREF
  char msg_info[256]; // [sp+450h] [bp-128h] BYREF

  memset(mac_filter_mode, 0, sizeof(mac_filter_mode));
  memset(ret_buf, 0, sizeof(ret_buf));
  memset(wifi_24g_enable, 0, sizeof(wifi_24g_enable));
  memset(wifi_5g_enable, 0, sizeof(wifi_5g_enable));
  memset(ifname_24g, 0, sizeof(ifname_24g));
  memset(ifname_5g, 0, sizeof(ifname_5g));
  memset(mib_name, 0, sizeof(mib_name));
  memset(msg_info, 0, sizeof(msg_info));
  Var = websGetVar(wp, "mac", &byte_794DF);
  v4 = websGetVar(wp, "devName", &byte_794DF);
  memset(cgi_debug, 0, 0x10u);
  if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
    printf(
      "%s[%s:%s:%d] %sget mac == %s\n\x1B[0m",
      "\x1B[0;33m",
      "cgi",
      "formAddMacfilterRule",
      1196,
      "\x1B[0;32m",
      Var);
  memset(cgi_debug, 0, 0x10u);
  if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
    printf(
      "%s[%s:%s:%d] %sget devName == %s\n\x1B[0m",
      "\x1B[0;33m",
      "cgi",
      "formAddMacfilterRule",
      1197,
      "\x1B[0;32m",
      v4);
  if ( *Var )
  {
    if ( set_device_name(v4, Var) )
      goto LABEL_84;
    memset(mac_filter_mode, 0, sizeof(mac_filter_mode));
    get_macfilter_mode(mac_filter_mode);
    memset(cgi_debug, 0, 0x10u);
    if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
      printf(
        "%s[%s:%s:%d] %sget mac filter mode: %s!\n\x1B[0m",
        "\x1B[0;33m",
        "cgi",
        "formAddMacfilterRule",
        1212,
        "\x1B[0;32m",
        mac_filter_mode);
    memset(s, 0, sizeof(s));
    memset(v28, 0, sizeof(v28));
    memset(v25, 0, sizeof(v25));
    memset(cgi_debug, 0, sizeof(cgi_debug));
    memset(v24, 0, sizeof(v24));
    snprintf((char *)v28, 0x80u, "macfilter.%s.id", mac_filter_mode);
    id_list = bm_get_id_list((char *)v28, s, 30);
    memset(v18, 0, sizeof(v18));
    if ( GetValue("cgi_debug", v18) && !strcmp("on", v18) )
      printf(
        "%s[%s:%s:%d] %sget %s rule num: %d\n\x1B[0m",
        "\x1B[0;33m",
        "cgi",
        "is_mac_existed_in_rule_list",
        1842,
        "\x1B[0;32m",
        mac_filter_mode,
        id_list);
    for ( i = 0; ; ++i )
    {
      v5 = i <= 29;
      if ( id_list <= 0 )
        v5 = 0;
      if ( !v5 )
        break;
      if ( s[i] )
      {
        snprintf(v25, 0x40u, "macfilter.%s.list%d", mac_filter_mode, s[i]);
        if ( !GetValue(v25, cgi_debug) )
        {
          printf(
            "%s[%s:%s:%d] %sget mib failed! [ %s ]\x1B[0m",
            "\x1B[0;33m",
            "cgi",
            "is_mac_existed_in_rule_list",
            1853,
            "\x1B[0;31m",
            v25);
          break;
        }
        memset(v18, 0, sizeof(v18));
        if ( GetValue("cgi_debug", v18) && !strcmp("on", v18) )
          printf(
            "%s[%s:%s:%d] %s%s == %s\n\x1B[0m",
            "\x1B[0;33m",
            "cgi",
            "is_mac_existed_in_rule_list",
            1856,
            "\x1B[0;32m",
            v25,
            cgi_debug);
        memset(v24, 0, sizeof(v24));
        _isoc99_sscanf(cgi_debug, "%s", v24);
        v6 = strlen(v24);
        if ( !strncasecmp(v24, Var, v6) )
        {
          printf(
            "%s[%s:%s:%d] %s%s is existed aready!\n\x1B[0m",
            "\x1B[0;33m",
            "cgi",
            "formAddMacfilterRule",
            1217,
            "\x1B[0;31m",
            Var);
          v7 = 0;
          goto finished_0;
        }
      }
    }
    memset(v28, 0, 0x78u);
    memset(cgi_debug, 0, sizeof(cgi_debug));
    snprintf(cgi_debug, 0x80u, "macfilter.%s.id", mac_filter_mode);
    v8 = bm_get_id_list(cgi_debug, v28, 30);
    memset(s, 0, 0x10u);
    if ( GetValue("cgi_debug", s) && !strcmp("on", (const char *)s) )
      printf(
        "%s[%s:%s:%d] %sget %s rule num: %d\n\x1B[0m",
        "\x1B[0;33m",
        "cgi",
        "get_macfilter_rule_index",
        1318,
        "\x1B[0;32m",
        mac_filter_mode,
        v8);
    if ( v8 <= 0 )
    {
      memset(s, 0, 0x10u);
      if ( GetValue("cgi_debug", s) && !strcmp("on", (const char *)s) )
        printf(
          "%s[%s:%s:%d] %sFirst rule of %s\n\x1B[0m",
          "\x1B[0;33m",
          "cgi",
          "get_macfilter_rule_index",
          1322,
          "\x1B[0;32m",
          mac_filter_mode);
      v10 = 1;
    }
    else
    {
      v9 = 0;
      while ( v28[v9++] )
      {
        if ( v9 == 30 )
        {
          v9 = 0;
          goto LABEL_44;
        }
      }
      memset(s, 0, 0x10u);
      if ( GetValue("cgi_debug", s) && !strcmp("on", (const char *)s) )
        printf(
          "%s[%s:%s:%d] %sget rule index of macfilter: %d\n\x1B[0m",
          "\x1B[0;33m",
          "cgi",
          "get_macfilter_rule_index",
          1331,
          "\x1B[0;32m",
          v9);
LABEL_44:
      memset(s, 0, 0x10u);
      if ( GetValue("cgi_debug", s) && !strcmp("on", (const char *)s) )
        printf(
          "%s[%s:%s:%d] %sget rule_index == %d\n\x1B[0m",
          "\x1B[0;33m",
          "cgi",
          "get_macfilter_rule_index",
          1336,
          "\x1B[0;32m",
          v9);
      v10 = v9;
    }
    if ( (unsigned int)(v10 - 1) > 0x1D )
    {
      memset(cgi_debug, 0, 0x10u);
      if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
        printf(
          "%s[%s:%s:%d] %sget invalid rule index: %d\n\x1B[0m",
          "\x1B[0;33m",
          "cgi",
          "formAddMacfilterRule",
          1225,
          "\x1B[0;32m",
          0);
      goto LABEL_84;
    }
    if ( strcmp("black", mac_filter_mode) )
    {
      printf(
        "%s[%s:%s:%d] %sDo not support add %s rule of macfilter!\n\x1B[0m",
        "\x1B[0;33m",
        "cgi",
        "formAddMacfilterRule",
        1237,
        "\x1B[0;31m",
        mac_filter_mode);
      goto LABEL_84;
    }
    memset(v28, 0, 0x40u);
    memset(cgi_debug, 0, sizeof(cgi_debug));
    snprintf((char *)v28, 0x40u, "macfilter.%s.list%d", mac_filter_mode, v10);
    snprintf(cgi_debug, 0x80u, "%s", Var);
    memset(s, 0, 0x10u);
    if ( GetValue("cgi_debug", s) && !strcmp("on", (const char *)s) )
      printf(
        "%s[%s:%s:%d] %sset rule %s == %s\n\x1B[0m",
        "\x1B[0;33m",
        "cgi",
        "set_macfilter_rule_to_list",
        1362,
        "\x1B[0;32m",
        (const char *)v28,
        cgi_debug);
    SetValue(v28, cgi_debug);
    memset(s, 0, 0x40u);
    memset(v28, 0, sizeof(v28));
    memset(cgi_debug, 0, sizeof(cgi_debug));
    snprintf((char *)s, 0x40u, "macfilter.%s.id", mac_filter_mode);
    GetValue(s, v28);
    memset(v25, 0, 0x10u);
    if ( GetValue("cgi_debug", v25) && !strcmp("on", v25) )
      printf(
        "%s[%s:%s:%d] %sget %s == %s!\n\x1B[0m",
        "\x1B[0;33m",
        "cgi",
        "add_id_to_rule_list_id",
        1389,
        "\x1B[0;32m",
        (const char *)s,
        (const char *)v28);
    if ( LOBYTE(v28[0]) )
    {
      strncpy(cgi_debug, (const char *)v28, 0x80u);
      snprintf((char *)v28, 0x80u, "%s,%d", cgi_debug, v10);
    }
    else
    {
      snprintf((char *)v28, 0x80u, "%d", v10);
    }
    memset(v25, 0, 0x10u);
    if ( GetValue("cgi_debug", v25) && !strcmp("on", v25) )
      printf(
        "%s[%s:%s:%d] %sset %s == %s\n\x1B[0m",
        "\x1B[0;33m",
        "cgi",
        "add_id_to_rule_list_id",
        1399,
        "\x1B[0;32m",
        (const char *)s,
        (const char *)v28);
    SetValue(s, v28);
    SetValue("filter.mac.en", "1");
    reload_macfilter_rules_to_wireless(mac_filter_mode);
    v12 = set_macfilter_mode(mac_filter_mode);
    if ( !CommitCfm(v12) )
    {
      printf(
        "%s[%s:%s:%d] %scfm commit error!\n\x1B[0m",
        "\x1B[0;33m",
        "cgi",
        "formAddMacfilterRule",
        1255,
        "\x1B[0;31m");
      goto LABEL_84;
    }
    doSystemCmd("cfm Post netctrl %d?op=%d", 9, 4);
    wifi_get_mib_radio(2, ifname_24g);
    wifi_get_mib_radio(5, ifname_5g);
    mibname = wifi_get_mibname(ifname_24g, "enable", mib_name);
    GetValue(mibname, wifi_24g_enable);
    v14 = wifi_get_mibname(ifname_5g, "enable", mib_name);
    GetValue(v14, wifi_5g_enable);
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
            "formAddMacfilterRule",
            1269,
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
            "formAddMacfilterRule",
            1275,
            "\x1B[0;32m");
        snprintf(msg_info, 0x100u, "op=%d,wl_rate=%d", 12, 2);
      }
    }
    else
    {
      if ( strcmp("1", wifi_5g_enable) )
      {
LABEL_85:
        v7 = 0;
        goto finished_0;
      }
      memset(cgi_debug, 0, 0x10u);
      if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
        printf(
          "%s[%s:%s:%d] %s5G is enabled, sending msg to 5G wifi refresh!\n\x1B[0m",
          "\x1B[0;33m",
          "cgi",
          "formAddMacfilterRule",
          1281,
          "\x1B[0;32m");
      snprintf(msg_info, 0x100u, "op=%d,wl_rate=%d", 12, 5);
    }
    send_msg_to_netctrl(19, msg_info);
    goto LABEL_85;
  }
  printf("%s[%s:%s:%d] %sget mac is NULL!\n\x1B[0m", "\x1B[0;33m", "cgi", "formAddMacfilterRule", 1200, "\x1B[0;31m");
LABEL_84:
  v7 = 1;
finished_0:
  sprintf(ret_buf, "{\"errCode\":%d}", v7);
  websTransfer(wp, ret_buf);
}
