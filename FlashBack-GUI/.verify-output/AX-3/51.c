/* =====================================================
 *  Path 51
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - mDMZSetCfg (arg=1, call_ea=0x4d494, func_ea=0x4d400, label=needs_check)
 *        call: GetValue("lan.ip", lanip);
 *    - fromAdvSetLanip (arg=1, call_ea=0x51ad8, func_ea=0x511bc, label=certain)
 *        call: SetValue("lan.ip", Var);
 *    - websGetVar (arg=ret, call_ea=0x51218, func_ea=source, label=source)
 *        call: Var = websGetVar(wp, "lanIp", "192.168.0.1");
 * ===================================================== */


/* Function: mDMZSetCfg @ 0x4D400 */
void __fastcall mDMZSetCfg(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r9
  char_t *v5; // r0
  bool v6; // zf
  int v7; // r2
  const char *v8; // r5
  in_addr_t v9; // r11
  int v10; // r0
  char_t lanip[16]; // [sp+0h] [bp-10h] BYREF
  char ret_buf[64]; // [sp+10h] [bp+0h] BYREF
  char param_str[260]; // [sp+50h] [bp+40h] BYREF

  memset(param_str, 0, 0x100u);
  memset(ret_buf, 0, sizeof(ret_buf));
  Var = websGetVar(wp, "dmzEn", "0");
  v5 = websGetVar(wp, "dmzIp", &byte_794DF);
  v6 = v5 == 0;
  if ( v5 )
    v6 = Var == 0;
  if ( !v6 )
  {
    v8 = v5;
    GetValue("lan.ip", lanip);
    v9 = inet_addr(v8);
    if ( v9 == inet_addr(lanip) )
    {
      v7 = 2;
      goto out;
    }
    SetValue("wan1.dmzen", Var);
    v10 = SetValue("wan1.dmzip", v8);
    if ( CommitCfm(v10) )
    {
      sprintf(param_str, "advance_type=%d", 1);
      send_msg_to_netctrl(5, param_str);
      v7 = 0;
      goto out;
    }
  }
  v7 = 1;
out:
  sprintf(ret_buf, "{\"errCode\":%d}", v7);
  websTransfer(wp, ret_buf);
}


/* Function: fromAdvSetLanip @ 0x511BC */
// local variable allocation has failed, the output may be wrong!
void __fastcall fromAdvSetLanip(webs_t wp, char_t *path, char_t *query)
{
  int v3; // r11
  char_t *Var; // r5
  char_t *v6; // r6
  char_t *v7; // r9
  char_t *v8; // r8
  char_t *v9; // r7
  bool v10; // zf
  int v11; // r10
  int v12; // r7
  const char *dipe; // [sp+18h] [bp-E0h]
  const char *dhlt; // [sp+1Ch] [bp-DCh]
  char_t *v15; // [sp+20h] [bp-D8h]
  char_t *v16; // [sp+24h] [bp-D4h]
  char oldip[16]; // [sp+30h] [bp-C8h] BYREF
  char oldmask[16]; // [sp+40h] [bp-B8h] BYREF
  char s[16]; // [sp+50h] [bp-A8h] BYREF
  char v20[16]; // [sp+60h] [bp-98h] BYREF
  char olden[16]; // [sp+70h] [bp-88h] OVERLAPPED BYREF
  char cgi_debug[16]; // [sp+80h] [bp-78h] BYREF
  char ret_buf[64]; // [sp+90h] [bp-68h] BYREF

  memset(ret_buf, 0, sizeof(ret_buf));
  GetValue("lan.ip", oldip);
  GetValue("lan.mask", oldmask);
  Var = websGetVar(wp, "lanIp", "192.168.0.1");
  v6 = websGetVar(wp, "lanMask", "255.255.255.0");
  memset(cgi_debug, 0, sizeof(cgi_debug));
  if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
    printf(
      "%s[%s:%s:%d] %sget lan_ip == %s, lan_mask == %s\n\x1B[0m",
      "\x1B[0;33m",
      "cgi",
      "fromAdvSetLanip",
      269,
      "\x1B[0;32m",
      Var,
      v6);
  if ( !strcmp(Var, "undefined") )
    Var = "192.168.0.1";
  SetValue("dhcps.gw", Var);
  if ( !strcmp(v6, "undefined") )
    v6 = "255.255.255.0";
  dipe = websGetVar(wp, "dhcpEn", "0");
  dhlt = websGetVar(wp, "startIp", "192.168.0.100");
  v15 = websGetVar(wp, "endIp", "192.168.0.200");
  v16 = websGetVar(wp, "leaseTime", "86400");
  memset(cgi_debug, 0, sizeof(cgi_debug));
  if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
    printf(
      "%s[%s:%s:%d] %sget dhcp_en == %s, dhcp_start == %s, dhcp_end == %s, dhcp_time == %s\n\x1B[0m",
      "\x1B[0;33m",
      "cgi",
      "fromAdvSetLanip",
      289,
      "\x1B[0;32m",
      dipe,
      dhlt,
      v15,
      v16);
  v7 = websGetVar(wp, "lanDnsAuto", "1");
  v8 = websGetVar(wp, "lanDns1", &byte_794DF);
  v9 = websGetVar(wp, "lanDns2", &byte_794DF);
  memset(cgi_debug, 0, sizeof(cgi_debug));
  if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
    printf(
      "%s[%s:%s:%d] %sdns auto: %s, dns1 == %s, dns2 == %s\n\x1B[0m",
      "\x1B[0;33m",
      "cgi",
      "fromAdvSetLanip",
      298,
      "\x1B[0;32m",
      v7,
      v8,
      v9);
  memset(s, 0, sizeof(s));
  memset(v20, 0, sizeof(v20));
  memset(olden, 0, sizeof(olden));
  GetValue("lan.dns.auto", olden);
  GetValue("lan.dns.hand1", s);
  GetValue("lan.dns.hand2", v20);
  v10 = v8 == 0;
  if ( v8 )
    v10 = v7 == 0;
  v11 = v10;
  if ( !v9 )
    v11 |= 1u;
  if ( !v11 )
  {
    v3 = strcmp(olden, v7);
    if ( v3 )
    {
      memset(cgi_debug, 0, sizeof(cgi_debug));
      if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
        printf(
          "%s[%s:%s:%d] %sdns setting changed!\n\x1B[0m",
          "\x1B[0;33m",
          "cgi",
          "check_lan_dns_change",
          213,
          "\x1B[0;32m");
      v3 = 1;
      SetValue("lan.dns.auto", v7);
    }
    if ( !strcmp(v7, "0") )
    {
      memset(cgi_debug, 0, sizeof(cgi_debug));
      if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
        printf("%s[%s:%s:%d] %sdns is menual!\n\x1B[0m", "\x1B[0;33m", "cgi", "check_lan_dns_change", 220, "\x1B[0;32m");
      if ( strcmp(s, v8) )
      {
        memset(cgi_debug, 0, sizeof(cgi_debug));
        if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
          printf(
            "%s[%s:%s:%d] %sdns1 changed: %s ==> %s\n\x1B[0m",
            "\x1B[0;33m",
            "cgi",
            "check_lan_dns_change",
            223,
            "\x1B[0;32m",
            s,
            v8);
        v3 = 1;
        SetValue("lan.dns.hand1", v8);
      }
      if ( strcmp(v20, v9) )
      {
        memset(cgi_debug, 0, sizeof(cgi_debug));
        if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
          printf(
            "%s[%s:%s:%d] %sdns2 changed: %s ==> %s\n\x1B[0m",
            "\x1B[0;33m",
            "cgi",
            "check_lan_dns_change",
            230,
            "\x1B[0;32m",
            v20,
            v9);
        v3 = 1;
        SetValue("lan.dns.hand2", v9);
      }
    }
  }
  GetValue("dhcps.en", olden);
  if ( !v3 && !atoi(olden) && !atoi(dipe) && !strcmp(Var, oldip) )
    goto out;
  changelanip(Var, v6, oldip, oldmask);
  memset(cgi_debug, 0, sizeof(cgi_debug));
  if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
    printf(
      "%s[%s:%s:%d] %sSET dhcps: enable == %s, pool_start == %s, pool_end == %s, leasetime == %s\n\x1B[0m",
      "\x1B[0;33m",
      "cgi",
      "fromAdvSetLanip",
      307,
      "\x1B[0;32m",
      dipe,
      dhlt,
      v15,
      v16);
  SetValue("dhcps.en", dipe);
  SetValue("dhcps.start", dhlt);
  SetValue("dhcps.end", v15);
  SetValue("dhcps.leasetime", v16);
  if ( !strcmp(oldip, Var) && !strcmp(oldmask, v6) )
  {
    v12 = 0;
  }
  else
  {
    memset(cgi_debug, 0, sizeof(cgi_debug));
    if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
      printf(
        "%s[%s:%s:%d] %slan ip changed: %s ==> %s, check wireless guest ip!\n\x1B[0m",
        "\x1B[0;33m",
        "cgi",
        "fromAdvSetLanip",
        319,
        "\x1B[0;32m",
        oldip,
        Var);
    v12 = 1;
    guest_ip_conflict_handle(Var, v6, 0);
  }
  memset(cgi_debug, 0, sizeof(cgi_debug));
  if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
    printf("%s[%s:%s:%d] %sset lan_ip == %s\n\x1B[0m", "\x1B[0;33m", "cgi", "fromAdvSetLanip", 323, "\x1B[0;32m", Var);
  SetValue("lan.ip", Var);
  memset(cgi_debug, 0, sizeof(cgi_debug));
  if ( GetValue("cgi_debug", cgi_debug) )
  {
    if ( !strcmp("on", cgi_debug) )
      printf(
        "%s[%s:%s:%d] %sset lan_mask == %s\n\x1B[0m",
        "\x1B[0;33m",
        "cgi",
        "fromAdvSetLanip",
        325,
        "\x1B[0;32m",
        v6);
  }
  SetValue("lan.mask", v6);
  if ( send_setlanipmsg_to_netctrl(wp, v12) != 1 )
  {
out:
    sprintf(ret_buf, "{\"errCode\":%d}", 0);
    websTransfer(wp, ret_buf);
  }
}
