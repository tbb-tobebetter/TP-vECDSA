/****************************************************************************
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#include "../global/global.hpp"
#include "../depends/hash.hpp"
#include "../depends/print.hpp"
#include "../depends/routines.hpp"

// define the structure of PP
struct YECDSA_PP
{  
    EC_POINT *g; 
};


// define keypair 
struct YECDSA_KP
{
    EC_POINT *pk; // define pk
    BIGNUM *sk;   // define sk
};

// define signature 
struct YECDSA_SIG
{
    BIGNUM *r; 
    BIGNUM *z;
};

struct YECDSA_Random
{
    BIGNUM *k;
};


/* allocate memory for PP */ 
void YECDSA_PP_new(YECDSA_PP &pp)
{ 
    pp.g = EC_POINT_new(group);  
}

/* free memory of PP */ 
void YECDSA_PP_free(YECDSA_PP &pp)
{ 
    EC_POINT_free(pp.g);
}

void YECDSA_KP_new(YECDSA_KP &keypair)
{
    keypair.pk = EC_POINT_new(group); 
    keypair.sk = BN_new(); 
}

void YECDSA_Random_new(YECDSA_Random &random)
{
    random.k = BN_new(); 
}

void YECDSA_KP_free(YECDSA_KP &keypair)
{
    EC_POINT_free(keypair.pk); 
    BN_free(keypair.sk);
}

void YECDSA_SIG_new(YECDSA_SIG &SIG)
{
    SIG.r = BN_new(); 
    SIG.z = BN_new();
}

void YECDSA_SIG_free(YECDSA_SIG &SIG)
{
    BN_free(SIG.r); 
    BN_free(SIG.z);
}


void YECDSA_PP_print(YECDSA_PP &pp)
{
    ECP_print(pp.g, "pp.g"); 
} 

void YECDSA_KP_print(YECDSA_KP &keypair)
{
    ECP_print(keypair.pk, "pk"); 
    BN_print(keypair.sk, "sk"); 
} 

void YECDSA_SIG_print(YECDSA_SIG &SIG)
{
    BN_print(SIG.r, "SIG.r");
    BN_print(SIG.z, "SIG.z");
} 


void YECDSA_SIG_serialize(YECDSA_SIG &SIG, ofstream &fout)
{
    BN_serialize(SIG.r, fout); 
    BN_serialize(SIG.z, fout); 
} 

void YECDSA_SIG_deserialize(YECDSA_SIG &SIG, ifstream &fin)
{
    BN_deserialize(SIG.r, fin); 
    BN_deserialize(SIG.z, fin); 
} 


/* Setup algorithm */ 
void YECDSA_Setup(YECDSA_PP &pp)
{ 
    EC_POINT_copy(pp.g, generator); 

//    #ifdef DEBUG
//    cout << "generate the public parameters for YECDSA Signature >>>" << endl; 
//    YECDSA_PP_print(pp); 
//    #endif
}

/* KeyGen algorithm */ 
void YECDSA_KeyGen(YECDSA_PP &pp, YECDSA_KP &keypair)
{ 
    BN_random(keypair.sk); // sk \sample Z_p
    EC_POINT_mul(group, keypair.pk, keypair.sk, NULL, NULL, bn_ctx); // pk = g^sk  

//    #ifdef DEBUG
//    cout << "key generation finished >>>" << endl;  
//    YECDSA_KP_print(keypair); 
//    #endif
}


void offline(YECDSA_PP &pp,YECDSA_Random &random, YECDSA_SIG &SIG)
{
	BIGNUM *k = BN_new();
    BN_random(k);  

    EC_POINT *K = EC_POINT_new(group);

    EC_POINT_mul(group, K, k, NULL, NULL, bn_ctx); // A = g^r
//    cout << "randomness k= >>>" <<k<< endl;
//    cout << "K= >>>" <<K<< endl;
    BIGNUM *rr_y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, K, SIG.r, rr_y, bn_ctx);
//    BN_print(SIG.r, "SIG.r");
//    BN_print(rr_y, "rr_y");
    BN_mod_inverse(random.k, k, order, bn_ctx);//temp_r=k^{-1}
    BN_free(k); 
    BN_free(rr_y);
    EC_POINT_free(K);
}

/* This function takes as input a message, returns a signature. */
void YECDSA_Sign(YECDSA_PP &pp, BIGNUM *&sk, string &message,YECDSA_Random &random, YECDSA_SIG &SIG)
{
    YECDSA_SIG sig; // define the signature

    //k^{-1}(e+sk*r_x)
    // compute e = H(m)
    BIGNUM *e = BN_new();
    Hash_String_to_BN(message, e);//e=H(m)

    BIGNUM *temp_sk = BN_new();
    BN_mul(temp_sk, sk, SIG.r, bn_ctx); //temp_sk=sk*r_x

    BIGNUM *temp_z = BN_new();
    BN_mod_add(temp_z,e,temp_sk,order,bn_ctx);//temp_z=e+sk*r_x

    BN_mod_mul(SIG.z, temp_z, random.k, order, bn_ctx); // z = temp_r*temp_z=k^{-1}(e+sk*r_x); 

//    #ifdef DEBUG
//        cout << "YECDSA signature generation finishes >>>" << endl;
//        YECDSA_SIG_print(SIG);  
//    #endif

    BN_free(e); 
    BN_free(temp_sk);
    BN_free(temp_z);
}


/* This function verifies the signature is valid for the message "msg_file" */

bool YECDSA_Verify(YECDSA_PP &pp, EC_POINT *&pk, string &message, YECDSA_SIG &SIG)
{
    bool Validity;       

    // compute e = H(A||m)
    BIGNUM *e = BN_new(); 
    Hash_String_to_BN(message, e);//e=h(m)
    
    BIGNUM *temp_z = BN_new();
    BN_mod_inverse(temp_z, SIG.z, order, bn_ctx);//temp_z=z^{-1}
    
    BIGNUM *temp_m = BN_new();
    BN_mod_mul(temp_m, temp_z, e, order, bn_ctx); // m = z^{-1}*e; 

    BIGNUM *temp_r_x = BN_new();
    BN_mod_mul(temp_r_x, temp_z, SIG.r, order, bn_ctx); // z^{-1}*r_x; 


    EC_POINT *LEFT = EC_POINT_new(group);
    EC_POINT *RIGHT = EC_POINT_new(group);

    EC_POINT_mul(group, LEFT, temp_m, NULL, NULL, bn_ctx); // LEFT = m*G 
    EC_POINT_mul(group, RIGHT, NULL, pk, temp_r_x, bn_ctx);   // RIGHT = r_x*pk
    EC_POINT_add(group, RIGHT, RIGHT, LEFT, bn_ctx);        // RIGHT = RIGHT+LEFT


    BIGNUM *rrr_x = BN_new();
    BIGNUM *rrr_y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, RIGHT, rrr_x, rrr_y, bn_ctx);
//    BN_print(rrr_x, "rrr_x");
//    BN_print(rrr_y, "rrr_y");

    if(BN_cmp(rrr_x,SIG.r)==0){
        Validity = true; 
    }
    else Validity = false; 


/* 
    #ifdef DEBUG
    if (Validity)
    {
        cout << "Signature is Valid >>>" << endl;
    }
    else
    {
        cout << "Signature is Invalid >>>" << endl;
    }
    #endif

*/

    BN_free(e); 
    BN_free(rrr_x);
    BN_free(rrr_y);
    BN_free(temp_z); 
    BN_free(temp_m);
    BN_free(temp_r_x);
    EC_POINT_free(LEFT);
    EC_POINT_free(RIGHT);  

    return Validity;
}