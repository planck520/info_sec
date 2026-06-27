/* =====================================================
 *  Path 54
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - get_routestatic_wisp_mode (arg=1, call_ea=0x4e94c, func_ea=0x4e820, label=needs_check)
 *        call: GetValue("wl.wisp.mask", wifi_status.wan_mask);
 *    - setStaticConfig (arg=1, call_ea=0x2e700, func_ea=0x2e620, label=needs_check)
 *        call: SetValue("wl.wisp.mask", v5);
 *    - websGetVar (arg=ret, call_ea=0x2e688, func_ea=source, label=source)
 *        call: v5 = websGetVar(wp, "mask", "0.0.0.0");
 * ===================================================== */


/* Function: get_routestatic_wisp_mode @ 0x4E820 */
void __fastcall get_routestatic_wisp_mode(cJSON_0 *object, char *work_mode)
{
  int v4; // r4
  cJSON *String; // r0
  cJSON *v6; // r2
  cJSON *v7; // r0
  char conn_type[16]; // [sp+0h] [bp-A0h] BYREF
  char wl_ifname[16]; // [sp+10h] [bp-90h] BYREF
  char wan_type[16]; // [sp+20h] [bp-80h] BYREF
  WAN_IP_INFO_STRU wifi_status; // [sp+30h] [bp-70h] BYREF

  memset(conn_type, 0, sizeof(conn_type));
  v4 = strcmp(work_mode, "wisp");
  if ( !v4 )
  {
    memset(wl_ifname, 0, sizeof(wl_ifname));
    memset(wan_type, 0, sizeof(wan_type));
    GetValue("wl.wisp.access_mode", conn_type);
    GetValue("wl.wisp.ifname", wl_ifname);
    memset(&wifi_status, 0, sizeof(wifi_status));
    if ( !strcmp(conn_type, "pppoe") )
    {
      v4 = 2;
      strcpy(wan_type, "2");
    }
    else if ( !strcmp(conn_type, "static") )
    {
      v4 = 1;
      strcpy(wan_type, "1");
    }
    else
    {
      strcpy(wan_type, "0");
    }
    if ( wifi_wisp_connect_check(wl_ifname, v4) == 3 )
    {
      GetValue("wl.wisp.mask", wifi_status.wan_mask);
      GetValue("wl.wisp.gateway", wifi_status.wan_gw);
      wifi_wisp_get_ip_info(v4, &wifi_status);
      String = cJSON_CreateString(wifi_status.wan_mask);
      cJSON_AddItemToObject((cJSON *)object, "wanMask", String);
      v6 = cJSON_CreateString(wifi_status.wan_gw);
    }
    else
    {
      v7 = cJSON_CreateString(&byte_794DF);
      cJSON_AddItemToObject((cJSON *)object, "wanMask", v7);
      v6 = cJSON_CreateString(&byte_794DF);
    }
    cJSON_AddItemToObject((cJSON *)object, "wanGateway", v6);
  }
}


/* Function: setStaticConfig @ 0x2E620 */
void __fastcall setStaticConfig(webs_t wp, int wan_id)
{
  char *Var; // r6
  char *v5; // r7
  char *v6; // r9
  char *v7; // r8
  char *v8; // r4
  char_t mib_name[256]; // [sp+0h] [bp-128h] BYREF

  memset(mib_name, 0, sizeof(mib_name));
  if ( wan_id == 1 )
  {
    Var = websGetVar(wp, "staticIp", "0.0.0.0");
    v5 = websGetVar(wp, "mask", "0.0.0.0");
    v6 = websGetVar(wp, "gateway", "0.0.0.0");
    v7 = websGetVar(wp, "dns1", &byte_794DF);
    v8 = websGetVar(wp, "dns2", &byte_794DF);
    SetValue("wl.wisp.access_mode", "static");
    SetValue("wl.wisp.ip", Var);
    SetValue("wl.wisp.mask", v5);
    SetValue("wl.wisp.gateway", v6);
    SetValue("wl.wisp.dns1", v7);
    SetValue("wl.wisp.dns2", v8);
    memset(mib_name, 0, sizeof(mib_name));
    sprintf(mib_name, "wan%d.ppoe.double.access", 1);
    SetValue(mib_name, "0");
  }
  else if ( wan_id == 2 )
  {
    Var = websGetVar(wp, "staticIp2", "0.0.0.0");
    v5 = websGetVar(wp, "mask2", "0.0.0.0");
    v6 = websGetVar(wp, "gateway2", "0.0.0.0");
    v7 = websGetVar(wp, "dns12", &byte_794DF);
    v8 = websGetVar(wp, "dns22", &byte_794DF);
  }
  else
  {
    v8 = 0;
    v7 = 0;
    v6 = 0;
    v5 = 0;
    Var = 0;
  }
  setWanValue(wan_id, "ip", Var);
  setWanValue(wan_id, "mask", v5);
  setWanValue(wan_id, "gateway", v6);
  setWanValue(wan_id, "dns1", v7);
  setWanValue(wan_id, "dns2", v8);
  guest_ip_conflict_handle(Var, v5, 8);
}
