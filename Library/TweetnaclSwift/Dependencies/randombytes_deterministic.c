
void randombytes(unsigned char *x,unsigned long long xlen)
{
  for (unsigned long long i = 0; i<xlen; i++) {
    x[i] = (unsigned char)3;
  }
}
