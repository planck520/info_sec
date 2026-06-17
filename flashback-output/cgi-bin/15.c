/* =====================================================
 *  Path 15
 *  vuln_type = CWE-120
 *  sink_func = sprintf
 *  source_func = websGetVar
 *  Hops:
 *    - sprintf (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - sub_41BDD8 (arg=2, call_ea=0x41be80, func_ea=0x41bdd8, label=certain)
 *        call: sprintf(v6, "ping %s -w %d &>/var/log/pingCheck", Var, v4);
 *    - websGetVar (arg=ret, call_ea=0x41be38, func_ea=source, label=source)
 *        call: Var = (const char *)websGetVar(a1, "ip", "www.baidu.com");
 * ===================================================== */


/* Function: sub_41BDD8 @ 0x41BDD8 */
int __fastcall sub_41BDD8(int a1)
{
  const char *Var; // $s2
  int v3; // $v0
  int v4; // $v0
  char v6[128]; // [sp+18h] [-80h] BYREF

  memset(v6, 0, sizeof(v6));
  Var = (const char *)websGetVar(a1, "ip", "www.baidu.com");
  v3 = websGetVar(a1, "num", &byte_431360);
  v4 = atoi(v3);
  sprintf(v6, "ping %s -w %d &>/var/log/pingCheck", Var, v4);
  doSystem(v6);
  setResponse(&word_42F754, "reserv");
  return 1;
}
