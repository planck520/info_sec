/* =====================================================
 *  Path 90
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formGetRouteStatic (arg=1, call_ea=0x4f1e0, func_ea=0x4f140, label=certain)
 *        call: GetValue("lan.mask", mib_value);
 *    - fromAdvSetLanip (arg=1, call_ea=0x51b64, func_ea=0x511bc, label=certain)
 *        call: SetValue("lan.mask", v6);
 *    - websGetVar (arg=ret, call_ea=0x51238, func_ea=source, label=source)
 *        call: v6 = websGetVar(wp, "lanMask", "255.255.255.0");
 * ===================================================== */


/* Function: formGetRouteStatic @ 0x4F140 */
void __fastcall formGetRouteStatic(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Object; // r4
  cJSON *String; // r0
  cJSON *v6; // r0
  cJSON *Array; // r7
  char *v8; // r5
  char_t *v9; // [sp+0h] [bp-14h]
  char_t *v10; // [sp+0h] [bp-14h]
  char work_mode[16]; // [sp+4h] [bp-10h] BYREF
  char lan_ip[32]; // [sp+14h] [bp+0h] BYREF
  char mib_value[256]; // [sp+34h] [bp+20h] BYREF
  ADVANCE_STATICROUTE_TABLE_CFG_STRU static_table; // [sp+134h] [bp+120h] BYREF

  memset(lan_ip, 0, sizeof(lan_ip));
  memset(mib_value, 0, sizeof(mib_value));
  memset(work_mode, 0, sizeof(work_mode));
  Object = cJSON_CreateObject();
  GetValue("lan.ip", lan_ip);
  String = cJSON_CreateString(lan_ip);
  cJSON_AddItemToObject(Object, "lanIp", String);
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("lan.mask", mib_value);
  v6 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "lanMask", v6);
  get_systerm_mode(work_mode);
  get_routestatic_route_mode((cJSON_0 *)Object, work_mode);
  get_routestatic_wisp_mode((cJSON_0 *)Object, work_mode);
  Array = cJSON_CreateArray();
  cJSON_AddItemToObject(Object, "routeList", Array);
  memset(&static_table, 0, sizeof(static_table));
  advance_get_static_table_cfg(&static_table);
  get_routestatic_basic((cJSON_0 *)Array, &static_table);
  get_routestatic_metric((cJSON_0 *)Array, &static_table, work_mode);
  v8 = cJSON_Print(Object);
  cJSON_Delete(Object);
  websWrite(wp, v9);
  websWrite(wp, v10);
  free(v8);
  websDone(wp, 200);
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
