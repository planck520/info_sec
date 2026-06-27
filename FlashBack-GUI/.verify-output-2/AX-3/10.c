/* =====================================================
 *  Path 10
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = read
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - bstrdup (arg=1, call_ea=0x16d04, func_ea=0x16cd8, label=needs_check)
 *        call: strcpy(v3, v1);
 *    - dbLoad (arg=0, call_ea=0x241b0, func_ea=0x23f98, label=needs_check)
 *        call: v13 = bstrdup(v18);
 *    - read (arg=1, call_ea=0x2407c, func_ea=source, label=source)
 *        call: v7 = read(v5, v6, sbuf.st_size);
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


/* Function: dbLoad @ 0x23F98 */
int __fastcall dbLoad(int did, char_t *filename, int flags)
{
  int v5; // r4
  void *v6; // r7
  ssize_t v7; // r0
  dbTable_t *v9; // r5
  int v10; // r6
  int v11; // r10
  char *v12; // r9
  char_t *v13; // r4
  char *v14; // r0
  char *v15; // r0
  char_t *v16; // r11
  char_t *v17; // r9
  char_t *v18; // r11
  int TableId; // r0
  int TableNrow; // r9
  int ColumnIndex; // r0
  _BOOL4 v22; // r3
  unsigned int v23; // r0
  char_t *fmta; // [sp+0h] [bp-A8h]
  char_t *fmt; // [sp+0h] [bp-A8h]
  char_t *path; // [sp+24h] [bp-84h] BYREF
  gstat_t sbuf; // [sp+28h] [bp-80h] BYREF

  basicGetProductDir();
  fmtAlloc(&path, 254, filename);
  trace(4, fmta);
  if ( stat_0(path, &sbuf) < 0 )
  {
    trace(3, fmt);
    bfree(path);
    return -1;
  }
  v5 = open(path, 0, 438);
  bfree(path);
  if ( v5 < 0 )
  {
    trace(3, fmt);
    return -1;
  }
  if ( sbuf.st_size <= 0 )
  {
    trace(3, fmt);
LABEL_9:
    close(v5);
    return -1;
  }
  v6 = balloc(sbuf.st_size + 1);
  v7 = read(v5, v6, sbuf.st_size);
  if ( v7 != sbuf.st_size )
  {
    trace(3, fmt);
    bfree(v6);
    goto LABEL_9;
  }
  close(v5);
  v9 = 0;
  v10 = -1;
  *((_BYTE *)v6 + sbuf.st_size) = 0;
  v11 = -1;
  v12 = strtok((char *)v6, "\n");
  v13 = 0;
  do
  {
    v14 = strrchr(v12, 10);
    if ( v14 || (v14 = strrchr(v12, 13)) != 0 )
      *v14 = 0;
    v15 = strchr(v12, 61);
    if ( v15 )
    {
      *v15 = 0;
      v16 = v15 + 1;
      v17 = trim(v12);
      v18 = trim(v16);
      if ( !strcmp(v17, "TABLE") )
      {
        if ( v13 )
          bfree(v13);
        v13 = bstrdup(v18);
        TableId = dbGetTableId(did, v13);
        v11 = TableId;
        if ( TableId < 0 )
          v9 = 0;
        else
          v9 = dbListTables[TableId];
      }
      else if ( !strcmp(v17, "ROW") )
      {
        if ( v11 >= 0 )
        {
          TableNrow = dbGetTableNrow(did, v13);
          if ( !dbSetTableNrow(did, v13, TableNrow + 1) )
            v10 = TableNrow;
        }
      }
      else if ( v10 != -1 )
      {
        ColumnIndex = GetColumnIndex(v11, v17);
        v22 = ColumnIndex >= 0;
        if ( !v9 )
          v22 = 0;
        if ( v22 )
        {
          if ( v9->columnTypes[ColumnIndex] == 1 )
          {
            dbWriteStr(did, v13, v17, v10, v18);
          }
          else
          {
            v23 = gstrtoi(v18);
            dbWriteInt(did, v13, v17, v10, v23);
          }
        }
      }
    }
    else
    {
      trace(5, fmt);
    }
    v12 = strtok(0, "\n");
  }
  while ( v12 );
  if ( v13 )
    bfree(v13);
  bfree(v6);
  return 0;
}
