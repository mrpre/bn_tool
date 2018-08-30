#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

#define MAX_BYTES 1024
unsigned char a[MAX_BYTES];
unsigned char b[MAX_BYTES];
unsigned char c[MAX_BYTES];
unsigned char d[MAX_BYTES];

void ec_mul_pub(unsigned char *curve, unsigned char *private)
{
        EC_POINT *r = NULL;
        EC_GROUP *group = NULL;
        BN_CTX *ctx = NULL;
        BIGNUM *pkey;
        int i, nid, len;

        if(NULL == (pkey = BN_new())) {
            printf("BN_new err\n");
            return;
        }

        if (NULL == (ctx = BN_CTX_new())) {
            printf("BN_CTX_new err\n");
            return;
        }

        if(!BN_hex2bn(&pkey, private))
        {
            printf("BN_hex2bn err\n");
            return;
        }

        if (!strncmp("secp192r1", curve, sizeof("secp192r1") - 1))
            nid = NID_X9_62_prime192v1;
        else if (!strncmp("secp256r1",curve, sizeof("secp256r1") - 1))
            nid = NID_X9_62_prime256v1;
        else 
            nid = OBJ_sn2nid(curve);

        if (nid == 0)
            nid = EC_curve_nist2nid(curve);
        if (nid == 0) {
            printf("unknow curve\n");
            return; 
        }

        group = EC_GROUP_new_by_curve_name(nid);

        if (NULL == (r = EC_POINT_new(group))) {
            printf("EC_POINT_new err\n");
            return;
        }

        if (!EC_POINT_mul(group, r, pkey, NULL, NULL, ctx)) {
            printf("EC_POINT_mul err\n");
            return;
        }

        len = EC_POINT_point2oct(group, r, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
        if (!len) {
            printf("EC_POINT_point2oct error 1\n");
            return;
        }
        printf("point len:%d\n", len);
        if (!EC_POINT_point2oct(group, r, POINT_CONVERSION_UNCOMPRESSED, a, len, NULL)) {
            printf("EC_POINT_point2oct error 2\n");
            return;
        }

        printf("x:");
        for (i = 1 ; i < (len-1)/2 + 1; i++) {
            printf("%02x", a[i]);
        }
        printf("\ny:");
        for (i = (len-1)/2 + 1 ; i < len; i++) {
            printf("%02x", a[i]);
        }
        printf("\n");
}

void mod_inv(unsigned char *a, unsigned char *p)
{
        BN_CTX *ctx = NULL;
        BIGNUM *ba, *bb, *bc;

        if(NULL == (ba = BN_new())
           || NULL == (bb = BN_new())
           || NULL == (bc = BN_new())
           || NULL == (ctx = BN_CTX_new())
           )
        {
            printf("BN_new err\n");
            return;
        }
 
        if(!BN_hex2bn(&ba, a)
           || !BN_hex2bn(&bb, p))
        {
            printf("BN_hex2bn err\n");
            return;
        }
        
        if(!BN_mod_inverse(bc, ba, bb, ctx))
        {
           printf("inverse err\n");
           return;
        }
        printf("ret 0x%s",BN_bn2hex(bc));
        printf("\n");
}
void mod_exp(unsigned char *a, unsigned char *p, unsigned char *m)
{
        BN_CTX *ctx = NULL;
	BIGNUM *ba, *bb, *bc, *bd;

        if(NULL == (ba = BN_new())
           || NULL == (bb = BN_new())
           || NULL == (bc = BN_new())
           || NULL == (bd = BN_new())
           || NULL == (ctx = BN_CTX_new())
           )
        {
            printf("BN_new err\n");
            return;
        }

        if(!BN_hex2bn(&ba, a)      
           || !BN_hex2bn(&bb, p))
        {
            printf("BN_hex2bn err\n");
            return;
        }

        if (m != NULL) 
        {
            BN_hex2bn(&bc, m);
            BN_mod_exp(bd, ba, bb, bc, ctx);
        }
        else
        {
            BN_exp(bd, ba, bb, ctx);
        }
        
        printf("0x%s",BN_bn2hex(bd));
        printf("\n");
}

void add_and_sub(unsigned char *a, unsigned char *p, unsigned char *m)
{
        BN_CTX *ctx = NULL;
        BIGNUM *ba, *bb, *bc, *bd;
        
        if(NULL == (ba = BN_new())
           || NULL == (bb = BN_new())
           || NULL == (bc = BN_new())
           || NULL == (bd = BN_new())
           || NULL == (ctx = BN_CTX_new())
           )
        {
            printf("BN_new err\n");
            return;
        }
        if(!BN_hex2bn(&ba, a)
           || !BN_hex2bn(&bb, p)
           || !BN_hex2bn(&bc, m))
        {
            printf("BN_hex2bn err\n");
            return;
        }

        BN_add(bd, ba, bb);
        BN_clear(ba);
        BN_sub(ba, bd, bc);
        printf("0x%s",BN_bn2hex(ba));
        printf("\n");
        
}

void mul_and_div(unsigned char *a, unsigned char *p, unsigned char *m)
{
        BN_CTX *ctx = NULL;
        BIGNUM *ba, *bb, *bc, *bd;

        if(NULL == (ba = BN_new())
           || NULL == (bb = BN_new())
           || NULL == (bc = BN_new())
           || NULL == (bd = BN_new())
           || NULL == (ctx = BN_CTX_new())
           )
        {
            printf("BN_new err\n");
            return;
        }

        if(!BN_hex2bn(&ba, a)
           || !BN_hex2bn(&bb, p)
           || !BN_hex2bn(&bc, m))
        {
            printf("BN_hex2bn err\n");
            return;
        }


        BN_mul(bd, ba, bb, ctx);
        BN_clear(ba);
        BN_clear(bb);
        BN_div(ba, bb, bd, bc, ctx);
        printf("Result divided by %s equal to :quotient:0x%s remainder:0x%s",m,BN_bn2hex(ba), BN_bn2hex(bb));
        printf("\n");

}

void main(int argc, unsigned char **argv)
{
        

        if (argc < 2)
            goto help;
        
        if (!strncmp("mod_exp", argv[1], 7) && argc == 5)
            mod_exp(argv[2], argv[3], argv[4]);   
        else if (!strncmp("mod_inv", argv[1], 7) && argc == 4)
            mod_inv(argv[2], argv[3]);
        else if (!strncmp("mod", argv[1], 3) && argc == 4)
            mod_exp(argv[2], "01", argv[3]);
        else if (!strncmp("exp", argv[1], 3) && argc == 4)
            mod_exp(argv[2], argv[3],NULL);
        else if (!strncmp("add", argv[1], 3) && argc == 4)
            add_and_sub(argv[2], argv[3], "00");
        else if (!strncmp("sub", argv[1], 3) && argc == 4)
            add_and_sub(argv[2], "00", argv[3]);
        else if (!strncmp("mul", argv[1], 3) && argc == 4)
            mul_and_div(argv[2], argv[3], "01");
        else if (!strncmp("div", argv[1], 3) && argc == 4)
            mul_and_div(argv[2], "01", argv[3]);
        else if (!strncmp("ec_mul", argv[1], 3) && argc == 4)
            ec_mul_pub(argv[2], argv[3]);
        else
            goto help;
        return ;
help:
       printf("Usage:\n");
       printf("To do [0aff ^ 0bab mod 0c1f]:          ./calc.o mod_exp \"0aff' \"0bab\" \"0c1f\" \n");
       printf("To do [0a ^ -1 mod 0b]:                ./calc.o mod_inv \"0a' \"0b\" \n");
       printf("To do [0a mod/add/sub/mul/div/exp 0b]: ./calc.o mod/add/sub/mul/div/exp \"0a' \"0b\" \n");
       printf("To do ec pub calc:                     ./calc.o ec_mulsecp 256k1 \"abcdefg..\"\n");
}
