/* =====================================================
 *  Path 13
 *  vuln_type = CWE-120
 *  sink_func = sprintf
 *  source_func = websGetVar
 *  Hops:
 *    - sprintf (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - sub_425328 (arg=2, call_ea=0x425408, func_ea=0x425328, label=needs_check)
 *        call: sprintf(v7, "HelpUrl_%s", Var);
 *    - websGetVar (arg=ret, call_ea=0x425384, func_ea=source, label=source)
 *        call: Var = (const char *)websGetVar(a1, "lang", "cn");
 * ===================================================== */


/* Function: sub_425328 @ 0x425328 */
int __fastcall sub_425328(int a1)
{
  const char *Var; // $s2
  int v3; // $s0
  int JsonConf; // $s1
  const char *v5; // $s0
  _BYTE v7[128]; // [sp+18h] [-80h] BYREF

  memset(v7, 0, sizeof(v7));
  Var = (const char *)websGetVar(a1, "lang", "cn");
  v3 = websGetVar(a1, "langAutoFlag", &word_42F754);
  nvram_set("preferred_lang", Var);
  nvram_set("auto_lang", v3);
  JsonConf = getJsonConf(0);
  if ( JsonConf )
  {
    sprintf(v7, "HelpUrl_%s", Var);
    v5 = (const char *)websGetVar(JsonConf, v7, &byte_431360);
    if ( *v5 )
    {
      memset(v7, 0, sizeof(v7));
      sprintf(v7, "http://%s", v5);
      nvram_set("help_url_custom", v7);
    }
    cJSON_Delete(JsonConf);
  }
  nvram_commit();
  setResponse(&word_42F754, "reserv");
  return 1;
}
