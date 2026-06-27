/* =====================================================
 *  Path 46
 *  vuln_type = CWE-120
 *  sink_func = sprintf
 *  source_func = websGetVar
 *  Hops:
 *    - sprintf (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - formSetClientState (arg=3, call_ea=0x5e40c, func_ea=0x5e2c0, label=needs_check)
 *        call: sprintf(buff, "%d;%s;%s;%s", v9, Var, v8, v6);
 *    - websGetVar (arg=ret, call_ea=0x5e32c, func_ea=source, label=source)
 *        call: Var = websGetVar(wp, "deviceId", &byte_794DF);
 * ===================================================== */


/* Function: formSetClientState @ 0x5E2C0 */
void __fastcall formSetClientState(webs_t wp, char_t *path, char_t *query)
{
  char *Var; // r8
  char_t *v5; // r11
  char_t *v6; // r10
  char_t *v7; // r0
  const char *v8; // r9
  int v9; // r2
  int rule_id; // [sp+Ch] [bp-124h] BYREF
  char ret_buf[32]; // [sp+10h] [bp-120h] BYREF
  char msg_info[256]; // [sp+30h] [bp-100h] BYREF
  char buff[516]; // [sp+130h] [bp+0h] BYREF

  memset(buff, 0, 0x200u);
  memset(msg_info, 0, sizeof(msg_info));
  memset(ret_buf, 0, sizeof(ret_buf));
  Var = websGetVar(wp, "deviceId", &byte_794DF);
  v5 = websGetVar(wp, "limitEn", "0");
  v6 = websGetVar(wp, "limitSpeed", "0");
  v7 = websGetVar(wp, "limitSpeedUp", "0");
  if ( Var )
  {
    v8 = v7;
    if ( get_client_qosrule_id(Var, &rule_id) == BEHAVIOR_FUNC_RET::eRET_FAILURE )
    {
      sprintf(ret_buf, "{\"errCode\":%d}", 1);
      goto LABEL_14;
    }
    v9 = atoi(v5);
    if ( v9 )
    {
      sprintf(buff, "%d;%s;%s;%s", v9, Var, v8, v6);
      if ( modify_add_qos_rule(rule_id, buff) || !CommitCfm(0) )
        goto LABEL_13;
      unSetQosOldMiblist();
      snprintf(msg_info, 0x100u, "op=%d", 6);
    }
    else
    {
      if ( delete_qos_rule(rule_id) || !CommitCfm(0) )
        goto LABEL_13;
      unSetQosOldMiblist();
      snprintf(msg_info, 0x100u, "op=%d", 5);
    }
    send_msg_to_netctrl(15, msg_info);
LABEL_13:
    sprintf(ret_buf, "{\"errCode\":%d}", 0);
    goto LABEL_14;
  }
  puts("[httpd] Device id is NULL!");
  sprintf(ret_buf, "{\"errCode\":%d}", -1);
LABEL_14:
  websTransfer(wp, ret_buf);
}
