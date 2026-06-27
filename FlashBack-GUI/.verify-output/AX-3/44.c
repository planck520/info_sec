/* =====================================================
 *  Path 44
 *  vuln_type = CWE-120
 *  sink_func = sprintf
 *  source_func = websGetVar
 *  Hops:
 *    - sprintf (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - set_device_name (arg=2, call_ea=0x4158c, func_ea=0x41428, label=needs_check)
 *        call: sprintf(mib_vlaue, "%s\t1", dev_name);
 *    - formSetDeviceName (arg=0, call_ea=0x5e264, func_ea=0x5e20c, label=needs_check)
 *        call: if ( set_device_name(v5, Var) )
 *    - websGetVar (arg=ret, call_ea=0x5e25c, func_ea=source, label=source)
 *        call: v5 = websGetVar(wp, "devName", &byte_794DF);
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


/* Function: formSetDeviceName @ 0x5E20C */
void __fastcall formSetDeviceName(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r7
  char_t *v5; // r0
  _BOOL4 v6; // r2
  char ret_buf[32]; // [sp+0h] [bp-38h] BYREF

  memset(ret_buf, 0, sizeof(ret_buf));
  Var = websGetVar(wp, "mac", &byte_794DF);
  v5 = websGetVar(wp, "devName", &byte_794DF);
  if ( set_device_name(v5, Var) )
  {
    sprintf(ret_buf, "{\"errCode\":%d}", 1);
  }
  else
  {
    v6 = CommitCfm(0) == 0;
    sprintf(ret_buf, "{\"errCode\":%d}", v6);
  }
  websTransfer(wp, ret_buf);
}
