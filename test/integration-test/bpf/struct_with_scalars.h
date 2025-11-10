struct relocated_struct_with_scalars {
#ifndef TARGET
  __u8 a;
#endif
  __u8 b;
  __u8 c;
#ifdef TARGET
  __u8 d;
#endif
};
