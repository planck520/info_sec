/* =====================================================
 *  Path 2
 *  vuln_type = CWE-78
 *  sink_func = doSystem
 *  source_func = websGetVar
 *  Hops:
 *    - doSystem (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - sub_41BF38 (arg=1, call_ea=0x41bf74, func_ea=0x41bf38, label=certain)
 *        call: doSystem("date -s '%s'", Var);
 *    - websGetVar (arg=ret, call_ea=0x41bf5c, func_ea=source, label=source)
 *        call: Var = (const char *)websGetVar(a1, "host_time", &byte_431360);
 * ===================================================== */


/* Function: sub_41BF38 @ 0x41BF38 */
int __fastcall sub_41BF38(int a1)
{
  const char *Var; // $v0

  Var = (const char *)websGetVar(a1, "host_time", &byte_431360);
  doSystem("date -s '%s'", Var);
  nvram_set_int("ntp_enable", 0);
  nvram_commit();
  setResponse(&word_42F754, "reserv");
  return 1;
}
