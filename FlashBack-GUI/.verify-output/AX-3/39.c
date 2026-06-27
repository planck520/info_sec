/* =====================================================
 *  Path 39
 *  vuln_type = CWE-120
 *  sink_func = memcpy
 *  source_func = read
 *  Hops:
 *    - memcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - brealloc (arg=1, call_ea=0x16d50, func_ea=0x16d14, label=needs_check)
 *        call: memcpy(v3, v2, *((_DWORD *)v2 - 2));
 *    - hAlloc (arg=0, call_ea=0x1a6f0, func_ea=0x1a650, label=certain)
 *        call: v12 = (char *)brealloc(v2, v11);
 *    - hAllocEntry (arg=0, call_ea=0x1a7c8, func_ea=0x1a7b8, label=certain)
 *        call: v6 = hAlloc(list);
 *    - dbAddRow (arg=0, call_ea=0x23770, func_ea=0x2370c, label=certain)
 *        call: return hAllocEntry((void ***)&v3->rows, &v3->nRows, 4 * v3->nColumns);
 *    - dbSetTableNrow (arg=1, call_ea=0x23928, func_ea=0x23898, label=needs_check)
 *        call: if ( dbAddRow(did, tablename) < 0 )
 *    - dbLoad (arg=1, call_ea=0x24214, func_ea=0x23f98, label=needs_check)
 *        call: if ( !dbSetTableNrow(did, v13, TableNrow + 1) )
 *    - read (arg=1, call_ea=0x2407c, func_ea=source, label=source)
 *        call: v7 = read(v5, v6, sbuf.st_size);
 * ===================================================== */


/* Function: brealloc @ 0x16D14 */
void *__fastcall brealloc(void *mp, int newsize)
{
  void *v2; // r5
  void *v3; // r0
  void *v4; // r4

  if ( !mp )
    return balloc(newsize);
  if ( newsize > *((_DWORD *)mp - 2) )
  {
    v2 = mp;
    v3 = balloc(newsize);
    v4 = v3;
    if ( v3 )
    {
      memcpy(v3, v2, *((_DWORD *)v2 - 2));
      bfree(v2);
    }
    return v4;
  }
  return mp;
}


/* Function: hAlloc @ 0x1A650 */
int __fastcall hAlloc(void ***map)
{
  void **v2; // r6
  void **v3; // r0
  char *v5; // r3
  char *v6; // r2
  void **v7; // r1
  int i; // r5
  void *v9; // t1
  char *v10; // r8
  int v11; // r4
  char *v12; // r0
  char *v13; // r6

  if ( *map )
  {
    v2 = *map - 2;
  }
  else
  {
    v3 = (void **)balloc(72);
    v2 = v3;
    if ( !v3 )
      return -1;
    memset(v3, 0, 0x48u);
    *v2 = (void *)16;
    v2[1] = 0;
    *map = v2 + 2;
  }
  v5 = (char *)*v2;
  v6 = (char *)v2[1];
  if ( (int)*v2 <= (int)v6 )
  {
    i = (int)*v2;
  }
  else
  {
    v7 = v2 + 1;
    for ( i = 0; i < (int)v5; ++i )
    {
      v9 = v7[1];
      ++v7;
      if ( !v9 )
      {
        v2[1] = v6 + 1;
        return i;
      }
    }
  }
  v10 = v5 + 16;
  v11 = 4 * (_DWORD)(v5 + 18);
  v12 = (char *)brealloc(v2, v11);
  v13 = v12;
  if ( !v12 )
    return -1;
  *map = (void **)(v12 + 8);
  *(_DWORD *)v12 = v10;
  memset(&v12[v11 - 64], 0, 0x40u);
  ++*((_DWORD *)v13 + 1);
  return i;
}


/* Function: hAllocEntry @ 0x1A7B8 */
int __fastcall hAllocEntry(void ***list, int *max, int size)
{
  int v6; // r4
  void *v7; // r0
  void *v8; // r8
  int result; // r0

  v6 = hAlloc(list);
  if ( v6 < 0 )
    return -1;
  if ( size > 0 )
  {
    v7 = balloc(size);
    v8 = v7;
    if ( !v7 )
    {
      hFree(list, v6);
      return -1;
    }
    memset(v7, 0, size);
    (*list)[v6] = v8;
  }
  result = v6;
  if ( v6 >= *max )
    *max = v6 + 1;
  return result;
}


/* Function: dbAddRow @ 0x2370C */
int __fastcall dbAddRow(int did, char_t *tablename)
{
  int TableId; // r0
  dbTable_t *v3; // r4
  char_t *v5; // [sp+0h] [bp-10h]

  TableId = dbGetTableId(0, tablename);
  if ( TableId < 0 )
    return -6;
  if ( TableId >= dbMaxTables )
    return -6;
  v3 = dbListTables[TableId];
  if ( !v3 )
    return -6;
  trace(5, v5);
  return hAllocEntry((void ***)&v3->rows, &v3->nRows, 4 * v3->nColumns);
}


/* Function: dbSetTableNrow @ 0x23898 */
int __fastcall dbSetTableNrow(int did, char_t *tablename, int nNewRows)
{
  int TableId; // r0
  dbTable_t *v7; // r5
  char_t *v9; // [sp+0h] [bp-18h]

  TableId = dbGetTableId(0, tablename);
  if ( TableId < 0 )
    return -6;
  if ( TableId >= dbMaxTables )
    return -6;
  v7 = dbListTables[TableId];
  if ( !v7 )
    return -6;
  if ( v7->nRows < nNewRows )
  {
    trace(4, v9);
    while ( nNewRows > v7->nRows )
    {
      if ( dbAddRow(did, tablename) < 0 )
        return -1;
    }
  }
  else
  {
    trace(4, v9);
  }
  return 0;
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
