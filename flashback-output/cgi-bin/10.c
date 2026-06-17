/* =====================================================
 *  Path 10
 *  vuln_type = CWE-120
 *  sink_func = sprintf
 *  source_func = websGetVar
 *  Hops:
 *    - sprintf (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - sub_41BC90 (arg=3, call_ea=0x41bd38, func_ea=0x41bc90, label=certain)
 *        call: sprintf(v6, "traceroute -m %d %s&>/var/log/traceRouteLog", v4, Var);
 *    - websGetVar (arg=ret, call_ea=0x41bcf0, func_ea=source, label=source)
 *        call: Var = (const char *)websGetVar(a1, "command", "www.baidu.com");
 * ===================================================== */


/* Function: sub_41BC90 @ 0x41BC90 */
int __fastcall sub_41BC90(int a1)
{
  const char *Var; // $s2
  int v3; // $v0
  int v4; // $v0
  char v6[128]; // [sp+18h] [-80h] BYREF

  memset(v6, 0, sizeof(v6));
  Var = (const char *)websGetVar(a1, "command", "www.baidu.com");
  v3 = websGetVar(a1, "num", &byte_431360);
  v4 = atoi(v3);
  sprintf(v6, "traceroute -m %d %s&>/var/log/traceRouteLog", v4, Var);
  doSystem(v6);
  setResponse(&word_42F754, "reserv");
  return 1;
}
