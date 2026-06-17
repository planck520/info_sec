/* =====================================================
 *  Path 11
 *  vuln_type = CWE-120
 *  sink_func = sprintf
 *  source_func = websGetVar
 *  Hops:
 *    - sprintf (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - sub_41D618 (arg=2, call_ea=0x41d938, func_ea=0x41d618, label=needs_check)
 *        call: sprintf(v17, "%s,%s,%s", v7, v8, v9);
 *    - websGetVar (arg=ret, call_ea=0x41d760, func_ea=source, label=source)
 *        call: v7 = (const char *)websGetVar(a1, "week", &word_42F754);
 * ===================================================== */


/* Function: sub_41D618 @ 0x41D618 */
int __fastcall sub_41D618(int a1)
{
  int Var; // $v0
  int v3; // $s2
  int v4; // $v0
  int v5; // $v0
  int v6; // $s4
  const char *v7; // $s7
  const char *v8; // $fp
  const char *v9; // $s6
  int v10; // $s5
  int v11; // $s3
  int v12; // $v0
  int v13; // $s1
  int v14; // $v0
  _DWORD v16[8]; // [sp+20h] [-40h] BYREF
  _DWORD v17[7]; // [sp+40h] [-20h] BYREF
  __int16 v18; // [sp+5Ch] [-4h]
  char v19; // [sp+5Eh] [-2h]

  memset(v16, 0, sizeof(v16));
  memset(v17, 0, sizeof(v17));
  v18 = 0;
  v19 = 0;
  Var = websGetVar(a1, "addEffect", &word_42F754);
  v3 = atoi(Var);
  if ( v3 == 1 )
  {
    v4 = websGetVar(a1, "enable", &word_42F754);
    v5 = atoi(v4);
    nvram_set_int("sch_parental_enable", v5);
  }
  else
  {
    v6 = websGetVar(a1, "mac", &byte_431360);
    v7 = (const char *)websGetVar(a1, "week", &word_42F754);
    v8 = (const char *)websGetVar(a1, "sTime", &word_42F754);
    v9 = (const char *)websGetVar(a1, "eTime", &word_42F754);
    v10 = websGetVar(a1, "state", &word_42F754);
    v11 = websGetVar(a1, "desc", &word_42F754);
    if ( v3 == 2 )
    {
      v12 = websGetVar(a1, "idx", &word_42F754);
      v13 = atoi(v12) - 1;
    }
    else
    {
      v13 = nvram_get_int("sch_parental_num");
      nvram_set_int("sch_parental_num", v13 + 1);
    }
    snprintf(v16, 32, "sch_parental_mac_x%d", v13);
    nvram_set(v16, v6);
    snprintf(v16, 32, "sch_parental_desc_x%d", v13);
    nvram_set(v16, v11);
    snprintf(v16, 32, "sch_parental_state_x%d", v13);
    v14 = atoi(v10);
    nvram_set_int(v16, v14);
    snprintf(v16, 32, "sch_parental_time_x%d", v13);
    sprintf(v17, "%s,%s,%s", v7, v8, v9);
    nvram_set(v16, v17);
  }
  nvram_commit();
  notify_rc("restart_firewall");
  setResponse(&word_42F754, "reserv");
  return 1;
}
