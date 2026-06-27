/* =====================================================
 *  Path 14
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - bstrdup (arg=1, call_ea=0x16d04, func_ea=0x16cd8, label=needs_check)
 *        call: strcpy(v3, v1);
 *    - dbWriteStr (arg=0, call_ea=0x23b7c, func_ea=0x23af0, label=certain)
 *        call: v11[v10] = (int)bstrdup(s);
 *    - umAddUser (arg=4, call_ea=0x21208, func_ea=0x210f4, label=certain)
 *        call: dbWriteStr(didUM, "users", "group", v11, group);
 *    - formAddUser (arg=2, call_ea=0x22c1c, func_ea=0x22adc, label=needs_check)
 *        call: umAddUser(Var, v5, v7, 0, v10);
 *    - websGetVar (arg=ret, call_ea=0x22b4c, func_ea=source, label=source)
 *        call: v7 = websGetVar(wp, "group", &byte_794DF);
 * ===================================================== */


/* Function: bstrdup @ 0x16CD8 */
char_t *__fastcall bstrdup(char_t *s)
{
  char_t *v1; // r4
  size_t v2; // r0
  char *v3; // r0
  char_t *v4; // r5

  v1 = s;
  if ( !s )
    v1 = &byte_794DF;
  v2 = strlen(v1);
  v3 = (char *)balloc(v2 + 1);
  v4 = v3;
  if ( v3 )
    strcpy(v3, v1);
  return v4;
}


/* Function: dbWriteStr @ 0x23AF0 */
int __fastcall dbWriteStr(int did, char_t *table, char_t *column, int row, char_t *s)
{
  int TableId; // r0
  dbTable_t *v8; // r4
  int ColumnIndex; // r0
  int v10; // r5
  int *v11; // r4
  void *v12; // r0

  TableId = dbGetTableId(0, table);
  if ( TableId < 0 )
    return -6;
  v8 = dbListTables[TableId];
  if ( !v8 )
    return -7;
  ColumnIndex = GetColumnIndex(TableId, column);
  v10 = ColumnIndex;
  if ( ColumnIndex < 0 )
    return -2;
  if ( v8->columnTypes[ColumnIndex] != 1 )
    return -8;
  if ( row < 0 || row >= v8->nRows )
    return -4;
  v11 = v8->rows[row];
  if ( !v11 )
    return -5;
  v12 = (void *)v11[ColumnIndex];
  if ( v12 )
    bfree(v12);
  v11[v10] = (int)bstrdup(s);
  return 0;
}


/* Function: umAddUser @ 0x210F4 */
int __fastcall umAddUser(char_t *user, char_t *pass, char_t *group, bool_t prot, bool_t disabled)
{
  int v8; // r10
  int v9; // r4
  int v10; // r0
  int v11; // r7
  char_t *v12; // r9

  v8 = prot;
  trace(3, user, pass);
  if ( umUserExists(user) )
    return -4;
  if ( !umCheckName(user) )
    return -6;
  if ( !umCheckName(pass) )
    return -7;
  if ( !umGroupExists(group) )
    return -2;
  v10 = dbAddRow(didUM, "users");
  v11 = v10;
  if ( v10 < 0 )
    return -1;
  v9 = dbWriteStr(didUM, "users", "name", v10, user);
  if ( v9 )
    return -1;
  v12 = bstrdup(pass);
  umEncryptString(v12);
  dbWriteStr(didUM, "users", "password", v11, v12);
  bfree(v12);
  dbWriteStr(didUM, "users", "group", v11, group);
  dbWriteInt(didUM, "users", "prot", v11, v8);
  dbWriteInt(didUM, "users", "disable", v11, disabled);
  return v9;
}


/* Function: formAddUser @ 0x22ADC */
void __fastcall formAddUser(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r6
  char_t *v5; // r7
  char_t *v6; // r10
  char_t *v7; // r8
  char_t *v8; // r9
  char_t *v9; // r11
  bool_t v10; // r0
  char_t *disableda; // [sp+0h] [bp-30h]

  Var = websGetVar(wp, "user", &byte_794DF);
  v5 = websGetVar(wp, "password", &byte_794DF);
  v6 = websGetVar(wp, "passconf", &byte_794DF);
  v7 = websGetVar(wp, "group", &byte_794DF);
  v8 = websGetVar(wp, "enabled", &byte_794DF);
  v9 = websGetVar(wp, "ok", &byte_794DF);
  websHeader(wp);
  websMsgStart(wp);
  if ( !strcmpci(v9, "ok") && !strcmp(v5, v6) )
  {
    v10 = !v8 || !*v8 || strcmp(v8, "on") != 0;
    umAddUser(Var, v5, v7, 0, v10);
    websWrite(wp, disableda);
  }
  else
  {
    websWrite(wp, (char_t *)wp, path, query);
  }
  websMsgEnd(wp);
  websFooter(wp);
  websDone(wp, 200);
}
