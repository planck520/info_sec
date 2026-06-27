/* =====================================================
 *  Path 43
 *  vuln_type = CWE-120
 *  sink_func = sprintf
 *  source_func = websGetVar
 *  Hops:
 *    - sprintf (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - set_device_name (arg=2, call_ea=0x4158c, func_ea=0x41428, label=needs_check)
 *        call: sprintf(mib_vlaue, "%s\t1", dev_name);
 *    - saveParentControlInfo (arg=0, call_ea=0x477f4, func_ea=0x47788, label=needs_check)
 *        call: set_device_name(v5, Var);
 *    - websGetVar (arg=ret, call_ea=0x477e0, func_ea=source, label=source)
 *        call: v5 = websGetVar(wp, "deviceName", &byte_794DF);
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


/* Function: saveParentControlInfo @ 0x47788 */
void __fastcall saveParentControlInfo(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r5
  char_t *v5; // r0
  parent_control_info *v6; // r6
  parent_control_info *v7; // r5
  int v8; // r9
  parent_control_info *v9; // r2
  int v10; // r1
  int id_list; // r0
  int v12; // r0
  char_t *v13; // [sp+0h] [bp-A0h]
  char_t *v14; // [sp+0h] [bp-A0h]
  int ruleid; // [sp+4h] [bp-9Ch] BYREF
  int pc_list[30]; // [sp+8h] [bp-98h] BYREF

  memset(pc_list, 0, sizeof(pc_list));
  ruleid = 0;
  Var = websGetVar(wp, "deviceId", &byte_794DF);
  v5 = websGetVar(wp, "deviceName", &byte_794DF);
  if ( *v5 )
    set_device_name(v5, Var);
  if ( !compare_parentcontrol_time(wp) )
  {
    v6 = (parent_control_info *)malloc(0x254u);
    memset(v6, 0, sizeof(parent_control_info));
    strcpy((char *)v6->mac_addr, Var);
    v7 = (parent_control_info *)malloc(0x254u);
    memset(v7, 0, sizeof(parent_control_info));
    SetValue("parent.global.en", "1");
    SetValue("filter.url.en", "1");
    SetValue("filter.mac.en", "1");
    get_parentControl_list_Info(wp, v7);
    v8 = getparentcontrolinfo(0, &ruleid, v6);
    if ( v8 <= 0 )
    {
      id_list = bm_get_id_list("parent.control.id", pc_list, 30);
      if ( id_list )
      {
        if ( id_list > 29 )
          goto LABEL_6;
        set_parentControl_list_Info(pc_list, v7, v8);
LABEL_13:
        free(v6);
        free(v7);
        CommitCfm(v12);
        send_msg_to_netctrl(9, "op=5");
        send_msg_to_netctrl(7, "op=5");
        send_msg_to_netctrl(14, "op=5");
        websWrite(wp, v13);
        goto LABEL_14;
      }
      SetValue("parent.control.id", "1");
      v9 = v7;
      v10 = 1;
      ruleid = 1;
    }
    else
    {
      if ( !memcmp(v6, v7, 0x254u) )
      {
LABEL_6:
        free(v6);
        free(v7);
        websWrite(wp, v13);
LABEL_14:
        websWrite(wp, v14);
        websDone(wp, 200);
        return;
      }
      v9 = v7;
      v10 = ruleid;
    }
    setparentcontrolinfo(v8, v10, v9);
    goto LABEL_13;
  }
}
