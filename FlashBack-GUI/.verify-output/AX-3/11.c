/* =====================================================
 *  Path 11
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - bstrdup (arg=1, call_ea=0x16d04, func_ea=0x16cd8, label=needs_check)
 *        call: strcpy(v3, v1);
 *    - dbWriteStr (arg=0, call_ea=0x23b7c, func_ea=0x23af0, label=certain)
 *        call: v11[v10] = (int)bstrdup(s);
 *    - umAddGroup (arg=4, call_ea=0x21308, func_ea=0x21274, label=certain)
 *        call: v9 = dbWriteStr(didUM, "groups", "name", v10, group);
 *    - formAddGroup (arg=0, call_ea=0x22808, func_ea=0x22624, label=needs_check)
 *        call: umAddGroup(Var, (__int16)v7, v16, 0, v17);
 *    - websGetVar (arg=ret, call_ea=0x22650, func_ea=source, label=source)
 *        call: Var = websGetVar(wp, "group", &byte_794DF);
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


/* Function: umAddGroup @ 0x21274 */
int __fastcall umAddGroup(char_t *group, __int16 priv, accessMeth_t am, bool_t prot, bool_t disabled)
{
  int v5; // r10
  int v8; // r8
  int v9; // r7
  int v10; // r0
  int v11; // r6

  v5 = priv;
  v8 = prot;
  trace(3, group, priv);
  if ( umGroupExists(group) )
    return -4;
  if ( !umCheckName(group) )
    return -6;
  v10 = dbAddRow(didUM, "groups");
  v11 = v10;
  if ( v10 < 0 )
    return -1;
  v9 = dbWriteStr(didUM, "groups", "name", v10, group);
  if ( v9 )
    return -1;
  dbWriteInt(didUM, "groups", "priv", v11, v5);
  dbWriteInt(didUM, "groups", "method", v11, am);
  dbWriteInt(didUM, "groups", "prot", v11, v8);
  dbWriteInt(didUM, "groups", "disable", v11, disabled);
  return v9;
}


/* Function: formAddGroup @ 0x22624 */
void __fastcall formAddGroup(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r6
  char_t *v5; // r8
  char_t *v6; // r7
  char_t *v7; // r9
  char_t *v8; // r10
  __int16 v9; // r5
  char_t *v10; // r10
  int v11; // r3
  int v12; // r11
  int v13; // t1
  const char *v14; // r0
  __int16 v15; // r0
  accessMeth_t v16; // r5
  bool_t v17; // r0
  char_t *disabled; // [sp+0h] [bp-38h]
  int v19; // [sp+Ch] [bp-2Ch]

  Var = websGetVar(wp, "group", &byte_794DF);
  v5 = websGetVar(wp, "method", &byte_794DF);
  v6 = websGetVar(wp, "enabled", &byte_794DF);
  v7 = websGetVar(wp, "privilege", &byte_794DF);
  v8 = websGetVar(wp, "ok", &byte_794DF);
  websHeader(wp);
  websMsgStart(wp);
  if ( !strcmpci(v8, "ok") && Var && *Var && !umGroupExists(Var) )
  {
    if ( v7 )
    {
      if ( *v7 )
      {
        v9 = 0;
        v10 = v7;
        v11 = 0;
        while ( 1 )
        {
          v13 = (unsigned __int8)*v10++;
          v12 = v13;
          if ( !v13 )
            break;
          if ( v12 == 32 )
          {
            *(v10 - 1) = v11;
            v14 = v7;
            v19 = v11;
            v7 = v10;
            v15 = atoi(v14);
            *(v10 - 1) = 32;
            v9 |= v15;
            v11 = v19;
          }
        }
        LOWORD(v7) = v9 | atoi(v7);
      }
      else
      {
        LOWORD(v7) = (unsigned __int8)*v7;
      }
    }
    if ( v5 && *v5 )
      v16 = atoi(v5);
    else
      v16 = AM_FULL;
    v17 = !v6 || !*v6 || strcmp(v6, "on") != 0;
    umAddGroup(Var, (__int16)v7, v16, 0, v17);
  }
  websWrite(wp, disabled);
  websMsgEnd(wp);
  websFooter(wp);
  websDone(wp, 200);
}
