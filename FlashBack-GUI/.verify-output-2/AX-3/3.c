/* =====================================================
 *  Path 3
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - formSetFirewallCfg (arg=1, call_ea=0x500d0, func_ea=0x50048, label=needs_check)
 *        call: strcpy(firewall_buf, Var);
 *    - websGetVar (arg=ret, call_ea=0x500a8, func_ea=source, label=source)
 *        call: Var = websGetVar(wp, "firewallEn", "1111");
 * ===================================================== */


/* Function: formSetFirewallCfg @ 0x50048 */
void __fastcall formSetFirewallCfg(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r4
  size_t v5; // r0
  char_t *fmt; // [sp+0h] [bp-58h]
  char_t *fmta; // [sp+0h] [bp-58h]
  char firewall_buf[8]; // [sp+8h] [bp-50h] BYREF
  char old_wan_ping_buf[8]; // [sp+10h] [bp-48h] BYREF
  char old_ddos_buf[64]; // [sp+18h] [bp-40h] BYREF
  char mib_value[68]; // [sp+58h] [bp+0h] BYREF

  memset(firewall_buf, 0, sizeof(firewall_buf));
  memset(old_ddos_buf, 0, sizeof(old_ddos_buf));
  memset(old_wan_ping_buf, 0, sizeof(old_wan_ping_buf));
  memset(mib_value, 0, 0x40u);
  Var = websGetVar(wp, "firewallEn", "1111");
  v5 = strlen(Var);
  if ( v5 > 3 )
  {
    strcpy(firewall_buf, Var);
    GetValue("security.ddos.map", old_ddos_buf);
    GetValue("firewall.pingwan", old_wan_ping_buf);
    sprintf(
      mib_value,
      "%c,1500;%c,1500;%c,1500",
      (unsigned __int8)firewall_buf[0],
      (unsigned __int8)firewall_buf[2],
      (unsigned __int8)firewall_buf[1]);
    SetValue("security.ddos.map", mib_value);
    SetValue("firewall.pingwan", &firewall_buf[3]);
    v5 = doSystemCmd("cfm post  netctrl ddos_ip_fence?op=6");
  }
  CommitCfm(v5);
  websWrite(wp, fmt);
  websWrite(wp, fmta);
  websDone(wp, 200);
}
