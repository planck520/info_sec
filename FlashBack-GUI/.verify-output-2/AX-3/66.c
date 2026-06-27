/* =====================================================
 *  Path 66
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - fromDhcpSetSer (arg=1, call_ea=0x526f8, func_ea=0x52634, label=needs_check)
 *        call: GetValue("dhcps.en", olden);
 *    - fromAdvSetLanip (arg=1, call_ea=0x5195c, func_ea=0x511bc, label=certain)
 *        call: SetValue("dhcps.en", dipe);
 *    - websGetVar (arg=ret, call_ea=0x5131c, func_ea=source, label=source)
 *        call: dipe = websGetVar(wp, "dhcpEn", "0");
 * ===================================================== */


/* Function: fromDhcpSetSer @ 0x52634 */
void __fastcall fromDhcpSetSer(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r7
  char_t *v5; // r10
  char_t *v6; // r9
  char_t *v7; // r0
  bool v8; // zf
  bool v9; // zf
  const char *v10; // r8
  int v11; // r2
  int v12; // r0
  int v13; // r0
  char_t olden[8]; // [sp+0h] [bp-190h] BYREF
  char dhcps_lease_time[32]; // [sp+8h] [bp-188h] BYREF
  char ret_buf[64]; // [sp+28h] [bp-168h] BYREF
  char param_str[256]; // [sp+68h] [bp-128h] BYREF

  memset(dhcps_lease_time, 0, sizeof(dhcps_lease_time));
  memset(ret_buf, 0, sizeof(ret_buf));
  Var = websGetVar(wp, "dhcpEn", "0");
  v5 = websGetVar(wp, "startIp", &byte_794DF);
  v6 = websGetVar(wp, "endIp", &byte_794DF);
  v7 = websGetVar(wp, "lease", &byte_794DF);
  v8 = v5 == 0;
  if ( v5 )
    v8 = Var == 0;
  if ( v8 )
    goto LABEL_11;
  v9 = v7 == 0;
  if ( v7 )
    v9 = v6 == 0;
  v10 = v7;
  if ( v9 )
  {
LABEL_11:
    v11 = -1;
  }
  else
  {
    GetValue("dhcps.en", olden);
    if ( atoi(olden) || atoi(Var) )
    {
      v12 = atoi(v10);
      sprintf(dhcps_lease_time, "%d", 3600 * v12);
      SetValue("dhcps.en", Var);
      SetValue("dhcps.start", v5);
      SetValue("dhcps.end", v6);
      SetValue("dhcps.leasetime", dhcps_lease_time);
      memset(param_str, 0, sizeof(param_str));
      sprintf(param_str, "op=%d,index=0", 3);
      v13 = send_msg_to_netctrl(3, param_str);
      CommitCfm(v13);
      v11 = 0;
    }
    else
    {
      v11 = 0;
    }
  }
  sprintf(ret_buf, "{\"errCode\":%d}", v11);
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
