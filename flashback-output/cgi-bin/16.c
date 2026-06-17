/* =====================================================
 *  Path 16
 *  vuln_type = CWE-120
 *  sink_func = sprintf
 *  source_func = websGetVar
 *  Hops:
 *    - sprintf (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - sub_419078 (arg=2, call_ea=0x41925c, func_ea=0x419078, label=certain)
 *        call: sprintf(v16, "%s:%s", v8, v9);
 *    - websGetVar (arg=ret, call_ea=0x4191c4, func_ea=source, label=source)
 *        call: v8 = websGetVar(a1, "sPort", (int)&byte_431360);
 * ===================================================== */


/* Function: sub_419078 @ 0x419078 */
int __fastcall sub_419078(int a1)
{
  char *Var; // $v0
  int v3; // $s2
  char *v4; // $v0
  int v5; // $s1
  char *v6; // $s4
  char *v7; // $fp
  char *v8; // $s3
  char *v9; // $s5
  char *v10; // $s6
  char *v11; // $s7
  int v12; // $s1
  char *v13; // $v0
  _BYTE v15[64]; // [sp+18h] [-88h] BYREF
  _BYTE v16[64]; // [sp+58h] [-48h] BYREF
  char *v17; // [sp+98h] [-8h]

  Var = websGetVar(a1, "addEffect", (int)&word_42F754);
  v3 = atoi(Var);
  v4 = websGetVar(a1, "enable", (int)&word_42F754);
  v5 = atoi(v4);
  memset(v15, 0, sizeof(v15));
  memset(v16, 0, sizeof(v16));
  if ( !v3 )
  {
    nvram_set_int("fw_lw_enable_x", v5 != 0);
LABEL_20:
    nvram_commit();
    notify_rc("restart_firewall");
    goto LABEL_21;
  }
  v6 = websGetVar(a1, "ip", (int)&byte_431360);
  v7 = websGetVar(a1, "proto", (int)&byte_431360);
  v8 = websGetVar(a1, "sPort", (int)&byte_431360);
  v9 = websGetVar(a1, "ePort", (int)&byte_431360);
  v17 = websGetVar(a1, "desc", (int)&byte_431360);
  v10 = websGetVar(a1, "time", (int)&byte_431360);
  v11 = websGetVar(a1, "date", (int)&byte_431360);
  sprintf(v16, "%s:%s", v8, v9);
  if ( v6 && v8 && v9 && (*v6 || *v8 || *v9) )
  {
    if ( v3 != 1 )
    {
      v12 = 0;
      if ( v3 == 2 )
      {
        v13 = websGetVar(a1, "idx", (int)&word_42F754);
        v12 = atoi(v13) - 1;
      }
      goto LABEL_14;
    }
    v12 = nvram_get_int("filter_lw_num_x");
    if ( v12 < 16 )
    {
      nvram_set_int("filter_lw_num_x", v12 + 1);
LABEL_14:
      sprintf(v15, "filter_lw_srcip_x%d", v12);
      nvram_set(v15, v6);
      sprintf(v15, "filter_lw_proto_x%d", v12);
      nvram_set(v15, v7);
      sprintf(v15, "filter_lw_dstport_x%d", v12);
      nvram_set(v15, v16);
      sprintf(v15, "filter_lw_desc_x%d", v12);
      nvram_set(v15, v17);
      sprintf(v15, "filter_lw_time_x%d", v12);
      if ( *v10 )
        nvram_set(v15, v10);
      else
        nvram_set(v15, "00002359");
      sprintf(v15, "filter_lw_date_x%d", v12);
      if ( *v11 )
        nvram_set(v15, v11);
      else
        nvram_set(v15, "1111111");
      goto LABEL_20;
    }
  }
LABEL_21:
  setResponse(&word_42F754, "reserv");
  return 1;
}
