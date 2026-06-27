/* =====================================================
 *  Path 15
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - bstrdup (arg=1, call_ea=0x16d04, func_ea=0x16cd8, label=needs_check)
 *        call: strcpy(v3, v1);
 *    - dbWriteStr (arg=0, call_ea=0x23b7c, func_ea=0x23af0, label=certain)
 *        call: v11[v10] = (int)bstrdup(s);
 *    - umAddAccessLimit (arg=4, call_ea=0x21a5c, func_ea=0x219dc, label=needs_check)
 *        call: if ( v9 < 0 || dbWriteStr(didUM, "access", "name", v9, url) < 0 )
 *    - formAddAccessLimit (arg=0, call_ea=0x2247c, func_ea=0x22328, label=needs_check)
 *        call: umAddAccessLimit(Var, v9, v10, v5);
 *    - websGetVar (arg=ret, call_ea=0x22350, func_ea=source, label=source)
 *        call: Var = websGetVar(wp, "url", &byte_794DF);
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


/* Function: umAddAccessLimit @ 0x219DC */
int __fastcall umAddAccessLimit(char_t *url, accessMeth_t am, __int16 secure, char_t *group)
{
  int v6; // r10
  int v9; // r0
  int v10; // r7

  v6 = secure;
  trace(3, url, am, secure);
  if ( umAccessLimitExists(url) )
    return -4;
  v9 = dbAddRow(didUM, "access");
  v10 = v9;
  if ( v9 < 0 || dbWriteStr(didUM, "access", "name", v9, url) < 0 )
    return -1;
  dbWriteInt(didUM, "access", "method", v10, am);
  dbWriteInt(didUM, "access", "secure", v10, v6);
  dbWriteStr(didUM, "access", "group", v10, group);
  return 0;
}


/* Function: formAddAccessLimit @ 0x22328 */
void __fastcall formAddAccessLimit(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r5
  char_t *v5; // r8
  char_t *v6; // r9
  char_t *v7; // r7
  char_t *v8; // r10
  accessMeth_t v9; // r6
  __int16 v10; // r2
  char_t *v11; // [sp+0h] [bp-20h]

  Var = websGetVar(wp, "url", &byte_794DF);
  v5 = websGetVar(wp, "group", &byte_794DF);
  v6 = websGetVar(wp, "method", &byte_794DF);
  v7 = websGetVar(wp, "secure", &byte_794DF);
  v8 = websGetVar(wp, "ok", &byte_794DF);
  websHeader(wp);
  websMsgStart(wp);
  if ( !strcmpci(v8, "ok") && Var && *Var && !umAccessLimitExists(Var) )
  {
    if ( v6 && *v6 )
      v9 = atoi(v6);
    else
      v9 = AM_FULL;
    if ( v7 )
    {
      v10 = (unsigned __int8)*v7;
      if ( *v7 )
        v10 = atoi(v7);
    }
    else
    {
      v10 = 0;
    }
    umAddAccessLimit(Var, v9, v10, v5);
  }
  websWrite(wp, v11);
  websMsgEnd(wp);
  websFooter(wp);
  websDone(wp, 200);
}
