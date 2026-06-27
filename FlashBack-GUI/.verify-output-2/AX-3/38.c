/* =====================================================
 *  Path 38
 *  vuln_type = CWE-120
 *  sink_func = strncpy
 *  source_func = websGetVar
 *  Hops:
 *    - strncpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - fromGstDhcpSetSer (arg=1, call_ea=0x5296c, func_ea=0x52820, label=certain)
 *        call: strncpy(val, v5, v11 + 1 - v12);
 *    - websGetVar (arg=ret, call_ea=0x52878, func_ea=source, label=source)
 *        call: v5 = websGetVar(wp, "dips", &byte_794DF);
 * ===================================================== */


/* Function: fromGstDhcpSetSer @ 0x52820 */
void __fastcall fromGstDhcpSetSer(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r11
  char_t *v5; // r7
  char_t *v6; // r10
  char_t *v7; // r9
  char_t *v8; // r8
  char_t *v9; // r6
  char *v10; // r8
  size_t v11; // r6
  size_t v12; // r0
  int v13; // r0
  char_t val[32]; // [sp+0h] [bp-48h] BYREF

  memset(val, 0, sizeof(val));
  Var = websGetVar(wp, "DHEN", "0");
  v5 = websGetVar(wp, "dips", &byte_794DF);
  v6 = websGetVar(wp, "dipe", &byte_794DF);
  v7 = websGetVar(wp, "DHLT", &byte_794DF);
  v8 = websGetVar(wp, "DS1", &byte_794DF);
  v9 = websGetVar(wp, "DS2", &byte_794DF);
  SetValue("dhcps.gst.1.en", Var);
  SetValue("dhcps.gst.1.start", v5);
  SetValue("dhcps.gst.1.end", v6);
  SetValue("dhcps.gst.1.leasetime", v7);
  SetValue("dhcps.gst.1.dns1", v8);
  SetValue("dhcps.gst.1.dns2", v9);
  v10 = strrchr(v5, 46);
  v11 = strlen(v5);
  v12 = strlen(v10);
  strncpy(val, v5, v11 + 1 - v12);
  strcat(val, "1");
  v13 = SetValue("lan.gst.1.ip", val);
  CommitCfm(v13);
  ask_to_reboot(wp, "network/lan_guest_dhcps.asp");
}
