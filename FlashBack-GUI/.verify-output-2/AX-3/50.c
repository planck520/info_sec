/* =====================================================
 *  Path 50
 *  vuln_type = CWE-120
 *  sink_func = memset
 *  source_func = websGetVar
 *  Hops:
 *    - memset (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - fromSysToolChangePwd (arg=0, call_ea=0x544e8, func_ea=0x543c4, label=needs_check)
 *        call: memset(v10, 0, 0x28u);
 *    - websGetVar (arg=ret, call_ea=0x54428, func_ea=source, label=source)
 *        call: v5 = websGetVar(wp, "SYSPS", &byte_794DF);
 * ===================================================== */


/* Function: fromSysToolChangePwd @ 0x543C4 */
void __fastcall fromSysToolChangePwd(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r9
  char_t *v5; // r7
  char_t *v6; // r10
  int v7; // r5
  char_t *v8; // r1
  int v9; // r0
  char *v10; // r6
  char pwd[32]; // [sp+0h] [bp-40h] BYREF

  memset(pwd, 0, sizeof(pwd));
  Var = websGetVar(wp, "SYSOPS", &byte_794DF);
  v5 = websGetVar(wp, "SYSPS", &byte_794DF);
  v6 = websGetVar(wp, "SYSPS2", &byte_794DF);
  GetValue("sys.userpass", pwd);
  if ( strcmp(pwd, Var) || (v7 = strcmp(v5, v6)) != 0 )
  {
    v8 = "/system_password.html?1";
  }
  else if ( !strcmp(Var, v5) )
  {
    v8 = "/system_password.html";
  }
  else
  {
    v9 = SetValue("sys.userpass", v5);
    CommitCfm(v9);
    getwebuserpwd(1);
    doSystemCmd("alipwdchange.sh");
    send_login_sta_update();
    do
    {
      v10 = &loginUserInfo[0].ip[v7];
      if ( !strcmp(&loginUserInfo[0].ip[v7], wp->ipaddr) )
      {
        memset(v10, 0, 0x28u);
        *((_DWORD *)v10 + 10) = 0;
      }
      v7 += 48;
    }
    while ( v7 != 144 );
    if ( *v5 )
      v8 = "/login.html";
    else
      v8 = "/main.html";
  }
  websRedirect(wp, v8);
}
