/* =====================================================
 *  Path 40
 *  vuln_type = CWE-120
 *  sink_func = memcpy
 *  source_func = read
 *  Hops:
 *    - memcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - ringqPutBlk (arg=1, call_ea=0x1bc7c, func_ea=0x1bbfc, label=needs_check)
 *        call: memcpy(rq->endp, v8, v7);
 *    - socketWrite (arg=1, call_ea=0x1c5ec, func_ea=0x1c55c, label=needs_check)
 *        call: ringqPutBlk(&v6->outBuf, (unsigned __int8 *)buf, v10);
 *    - websWriteBlock (arg=1, call_ea=0x24c00, func_ea=0x24ba0, label=needs_check)
 *        call: v8 = socketWrite(wp->sid, v7, v4);
 *    - websCgiGatherOutput (arg=1, call_ea=0x17458, func_ea=0x173b0, label=needs_check)
 *        call: websWriteBlock(wp, cgiBuf, v4);
 *    - read (arg=1, call_ea=0x17440, func_ea=source, label=source)
 *        call: while ( 1 )
 * ===================================================== */


/* Function: ringqPutBlk @ 0x1BBFC */
int __fastcall ringqPutBlk(ringq_t *rq, unsigned __int8 *buf, int size)
{
  int v6; // r7
  signed int v7; // r5
  unsigned __int8 *v8; // r1
  unsigned __int8 *endbuf; // r2
  unsigned __int8 *v10; // r3

  v6 = 0;
  while ( size > 0 )
  {
    if ( size <= ringqPutBlkMax(rq) )
      goto LABEL_8;
    v7 = ringqPutBlkMax(rq);
    if ( v7 <= 0 )
    {
      if ( !ringqGrow(rq) )
        return v6;
      if ( size <= ringqPutBlkMax(rq) )
      {
LABEL_8:
        v7 = size;
        goto LABEL_9;
      }
      v7 = ringqPutBlkMax(rq);
    }
LABEL_9:
    v8 = buf;
    buf += v7;
    memcpy(rq->endp, v8, v7);
    size -= v7;
    endbuf = rq->endbuf;
    v6 += v7;
    v10 = &rq->endp[v7];
    rq->endp = v10;
    if ( v10 >= endbuf )
      rq->endp = rq->buf;
  }
  return v6;
}


/* Function: socketWrite @ 0x1C55C */
int __fastcall socketWrite(int sid, char *buf, int bufsize)
{
  socket_t *v6; // r9
  int v7; // r4
  int v9; // r0
  int v10; // r5

  v6 = socketPtr(sid);
  if ( !v6 )
    return -1;
  v7 = 0;
  while ( bufsize > 0 )
  {
    v9 = ringqPutBlkMax(&v6->outBuf);
    if ( v9 )
    {
      if ( bufsize < v9 )
        v10 = bufsize;
      else
        v10 = v9;
      ringqPutBlk(&v6->outBuf, (unsigned __int8 *)buf, v10);
      v7 += v10;
      bufsize -= v10;
      buf += v10;
    }
    else
    {
      if ( socketFlush(sid) < 0 )
        return -1;
      if ( !ringqPutBlkMax(&v6->outBuf) && (v6->flags & 0x80) == 0 )
        return v7;
    }
  }
  return v7;
}


/* Function: websWriteBlock @ 0x24BA0 */
int __fastcall websWriteBlock(webs_t wp, char_t *buf, int nChars)
{
  int v4; // r5
  int v5; // r4
  char *v6; // r7
  char_t *v7; // r8
  int v8; // r9

  v4 = nChars;
  v5 = 0;
  v6 = ballocUniToAsc(buf, nChars);
  v7 = v6;
  while ( v4 > 0 )
  {
    if ( (wp->flags & 0x8000) != 0 )
    {
      v8 = websSSLWrite(wp->wsp, v7, v4);
      if ( v8 < 0 )
        goto LABEL_7;
      websSSLFlush(wp->wsp);
    }
    else
    {
      v8 = socketWrite(wp->sid, v7, v4);
      if ( v8 < 0 )
      {
LABEL_7:
        bfree(v6);
        return -1;
      }
      socketFlush(wp->sid);
    }
    v4 -= v8;
    v7 += v8;
    v5 += v8;
  }
  bfree(v6);
  return v5;
}


/* Function: websCgiGatherOutput @ 0x173B0 */
void __fastcall websCgiGatherOutput(cgiRec *cgip)
{
  int v2; // r5
  websRec *wp; // r8
  ssize_t v4; // r0
  ssize_t v5; // r6
  gstat_t sbuf; // [sp+0h] [bp-170h] BYREF
  char_t cgiBuf[254]; // [sp+58h] [bp-118h] BYREF

  if ( !stat_0(cgip->stdOut, &sbuf) && sbuf.st_size > cgip->fplacemark )
  {
    v2 = open(cgip->stdOut, 0, 292);
    if ( v2 >= 0 )
    {
      wp = cgip->wp;
      if ( !cgip->fplacemark )
        websWrite(cgip->wp, (char_t *)sbuf.st_dev);
      lseek(v2, cgip->fplacemark, 0);
      while ( 1 )
      {
        v4 = read(v2, cgiBuf, 0xFEu);
        v5 = v4;
        if ( v4 <= 0 )
          break;
        websWriteBlock(wp, cgiBuf, v4);
        cgip->fplacemark += v5;
      }
    }
    close(v2);
  }
}
