/* =====================================================
 *  Path 48
 *  vuln_type = CWE-120
 *  sink_func = sprintf
 *  source_func = websGetVar
 *  Hops:
 *    - sprintf (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - fromAddressNat (arg=2, call_ea=0x4f3bc, func_ea=0x4f2e8, label=certain)
 *        call: v7 = sprintf(gotopage, "advance/addressNatList.asp?page=%s", v6);
 *    - websGetVar (arg=ret, call_ea=0x4f3a8, func_ea=source, label=source)
 *        call: v6 = websGetVar(wp, "page", "1");
 * ===================================================== */


/* Function: fromAddressNat @ 0x4F2E8 */
void __fastcall fromAddressNat(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r9
  char_t *v5; // r0
  char_t *v6; // r0
  int v7; // r0
  char_t gotopage[256]; // [sp+0h] [bp-100h] BYREF
  char param_str[256]; // [sp+100h] [bp+0h] BYREF
  char list[516]; // [sp+200h] [bp+100h] BYREF

  memset(gotopage, 0, sizeof(gotopage));
  memset(list, 0, 0x200u);
  memset(param_str, 0, sizeof(param_str));
  Var = websGetVar(wp, "entrys", &byte_794DF);
  v5 = websGetVar(wp, "mitInterface", &byte_794DF);
  sprintf(list, "%s;%s", Var, v5);
  save_list_data("adv.addrnat", list, 126);
  v6 = websGetVar(wp, "page", "1");
  v7 = sprintf(gotopage, "advance/addressNatList.asp?page=%s", v6);
  if ( CommitCfm(v7) )
  {
    sprintf(param_str, "advance_type=%d", 7);
    send_msg_to_netctrl(5, param_str);
  }
  websRedirect(wp, gotopage);
}
