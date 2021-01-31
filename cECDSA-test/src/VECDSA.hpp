/****************************************************************************
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#include "../global/global.hpp"
#include "../depends/hash.hpp"
#include "../depends/print.hpp"
#include "../depends/routines.hpp"
//#include <typeinfo>
#include<iostream>
#include<ctime>



// define the structure of PP
struct VECDSA_PP
{  
    EC_POINT *G; 
};


// define keypair 
struct VECDSA_KP
{
    EC_POINT *pk_1;
    EC_POINT *pk_2; // define pk
    BIGNUM *sk_1;
    BIGNUM *sk_2;   // define sk
};

// define signature 
struct VECDSA_SIG
{
    BIGNUM *r; 
    BIGNUM *z;
};


struct VECDSA_Random
{
    BIGNUM *k; 
};


/* allocate memory for PP */ 
void VECDSA_PP_new(VECDSA_PP &pp)
{ 
    pp.G = EC_POINT_new(group);  
}

/* free memory of PP */ 
void VECDSA_PP_free(VECDSA_PP &pp)
{ 
    EC_POINT_free(pp.G);
}

void VECDSA_KP_new(VECDSA_KP &keypair)
{
    keypair.pk_1 = EC_POINT_new(group); 
    keypair.pk_2 = EC_POINT_new(group);
    keypair.sk_1 = BN_new(); 
    keypair.sk_2 = BN_new();
}

void VECDSA_KP_free(VECDSA_KP &keypair)
{
    EC_POINT_free(keypair.pk_1);
    EC_POINT_free(keypair.pk_2);
    BN_free(keypair.sk_1); 
    BN_free(keypair.sk_2);
}

void VECDSA_SIG_new(VECDSA_SIG &SIG)
{
    SIG.r = BN_new(); 
    SIG.z = BN_new();
}

void VECDSA_Random_new(VECDSA_Random &Random)
{
    Random.k = BN_new(); 
}

void VECDSA_SIG_free(VECDSA_SIG &SIG)
{
    BN_free(SIG.r); 
    BN_free(SIG.z);
}


void VECDSA_PP_print(VECDSA_PP &pp)
{
    ECP_print(pp.G, "pp.G"); 
} 

void VECDSA_KP_print(VECDSA_KP &keypair)
{
    ECP_print(keypair.pk_1, "pk_1"); 
    ECP_print(keypair.pk_2, "pk_2"); 
    BN_print(keypair.sk_1, "sk_1"); 
    BN_print(keypair.sk_2, "sk_2");
} 

void VECDSA_SIG_print(VECDSA_SIG &SIG)
{
    BN_print(SIG.r, "SIG.r");
    BN_print(SIG.z, "SIG.z");
} 


//void VECDSA_SIG_serialize(VECDSA_SIG &SIG, ofstream &fout)
//{
//   ECP_serialize(SIG.A, fout); 
//   BN_serialize(SIG.z, fout); 
//} 

//void VECDSA_SIG_deserialize(VECDSA_SIG &SIG, ifstream &fin)
//{
//   ECP_deserialize(SIG.A, fin); 
//   BN_deserialize(SIG.z, fin); 
//} 


/* Setup algorithm */ 
void VECDSA_Setup(VECDSA_PP &pp)
{ 
    EC_POINT_copy(pp.G, generator); 

//    #ifdef DEBUG
  //  cout << "generate the public parameters for VECDSA Signature >>>" << endl; 
  //  VECDSA_PP_print(pp); 
  //  #endif
}

/* KeyGen algorithm */ 
void VECDSA_KeyGen(VECDSA_PP &pp, VECDSA_KP &keypair)
{   
    BN_random(keypair.sk_1); // sk_1 \sample Z_p
    BN_random(keypair.sk_2); // sk_2 \sample Z_p
    BIGNUM *temp_sk1 = BN_new();
    BIGNUM *temp_sk2 = BN_new();
    BN_mod_add(temp_sk1, keypair.sk_1, keypair.sk_2, order, bn_ctx);//sk1=sk1+sk2
    BN_mod_mul(temp_sk2, keypair.sk_1, keypair.sk_2, order, bn_ctx);//temp_sk=sk1*sk2
    EC_POINT_mul(group, keypair.pk_1, temp_sk1, NULL, NULL, bn_ctx); // pk_1 = sk1*G=(sk1+sk2)G
    EC_POINT_mul(group, keypair.pk_2, temp_sk2, NULL, NULL, bn_ctx); // pk_2 = keypair.sk_2*G=(sk1*sk2)G 
    
    BN_free(temp_sk1);
    BN_free(temp_sk2);

//    #ifdef DEBUG
//    cout << "key generation finished >>>" << endl;  
//    VECDSA_KP_print(keypair); 
//   #endif
}

void offline(VECDSA_PP &pp, VECDSA_Random &Random, VECDSA_SIG &SIG)
{
    BIGNUM *kk = BN_new();
    BN_random(kk);  

    EC_POINT *K = EC_POINT_new(group);
    EC_POINT_mul(group, K, kk, NULL, NULL, bn_ctx); // K = k*G

    
    BIGNUM *r_y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, K, SIG.r, r_y, bn_ctx);
  
    BN_mod_inverse(Random.k, kk, order, bn_ctx);//Random.k=k^{-1}

    BN_free(kk);
    BN_free(r_y);
    EC_POINT_free(K);
}



/* This function takes as input a message, returns a signature. */
void VECDSA_Sign(VECDSA_PP &pp, BIGNUM *&sk_1, BIGNUM *&sk_2, string &message, VECDSA_Random &Random, VECDSA_SIG &SIG)
{
    VECDSA_SIG sig; // define the signature

    // compute e = H(m)
    BIGNUM *e = BN_new();
    Hash_String_to_BN(message, e);//e=H(m)

    BIGNUM *temp_sk_2 = BN_new();
    BN_mod_mul(temp_sk_2, sk_2, SIG.r,order, bn_ctx); //temp_sk_2=sk_2*r_x


    BIGNUM *temp_z_2 = BN_new();
    BN_mod_add(temp_z_2,e,temp_sk_2,order,bn_ctx);//temp_z_2=e+sk_2*r_x

    BIGNUM *temp_sk_1 = BN_new();
    BN_mod_mul(temp_sk_1, sk_1, SIG.r,order, bn_ctx); //temp_sk_1=sk_1*r_x

    BIGNUM *temp_z_1 = BN_new();
    BN_mod_add(temp_z_1,e,temp_sk_1,order,bn_ctx);//temp_z_1=e+sk_1*r_x

    BIGNUM *z_1 = BN_new();
    BN_mod_mul(z_1, temp_z_1, Random.k, order, bn_ctx); // z_1 = k^{-1}(e+sk_1*r_x);

    BN_mod_mul(SIG.z, z_1, temp_z_2, order, bn_ctx); // z =z_1*temp_z_2= k^{-1}(e+sk_1*r_x)(e+sk_2*r_x);


//    #ifdef DEBUG
//        cout << "VECDSA signature generation finishes >>>" << endl;
//        VECDSA_SIG_print(SIG);  
//    #endif


    BN_free(e);
    BN_free(temp_sk_1);
    BN_free(temp_sk_2);
    BN_free(temp_z_1);
    BN_free(temp_z_2);
    BN_free(z_1);

}


/* This function verifies the signature is valid for the message "msg_file" */

bool VECDSA_Verify(VECDSA_PP &pp, EC_POINT *&pk_1,EC_POINT *&pk_2, string &message, VECDSA_SIG &SIG)
{
    bool Validity;       
    //z^{-1}

    BIGNUM *temp_z = BN_new();
    BN_mod_inverse(temp_z, SIG.z, order, bn_ctx);//temp_z=z^{-1}

    // compute e = H(m)
    BIGNUM *e = BN_new(); 
    Hash_String_to_BN(message, e);//e=H(m)
    
    BIGNUM *temp_m = BN_new();
    BN_sqr(temp_m, e, bn_ctx);//m^2

    BN_mod_mul(temp_m, temp_z, temp_m, order, bn_ctx); // m = z^{-1}*m^2; 

    BIGNUM *temp_r = BN_new();
    BN_mod_mul(temp_r, e, SIG.r, order, bn_ctx); // temp_r = r_x*e; 
    BN_mod_mul(temp_r, temp_z, temp_r, order, bn_ctx); // m = z^{-1}*r_x*e; 

    BIGNUM *temp_rr = BN_new();
    BN_sqr(temp_rr, SIG.r, bn_ctx);//r_x^2
    BN_mod_mul(temp_rr, temp_z, temp_rr, order, bn_ctx); // m = z^{-1}*r_x^2; 


    EC_POINT *G1 = EC_POINT_new(group);
    EC_POINT *G2 = EC_POINT_new(group);
    EC_POINT *G3 = EC_POINT_new(group);

    EC_POINT_mul(group, G1, temp_m, NULL, NULL, bn_ctx); // G1 = z^{-1}*m^2*G 
    EC_POINT_mul(group, G2, NULL, pk_1, temp_r, bn_ctx);   // G2= z^{-1}*r_x*h(m)*pk_1
    EC_POINT_mul(group, G3, NULL, pk_2, temp_rr, bn_ctx);   // G3 = z^{-1}*r_x^{2}*pk_1

    EC_POINT_add(group, G1, G1, G2, bn_ctx);        // G1 = G1+G2
    EC_POINT_add(group, G1, G1, G3, bn_ctx);        // G1 = G1+G3

    BIGNUM *rr_x = BN_new();
    BIGNUM *rr_y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, G1, rr_x, rr_y, bn_ctx);



    if(BN_cmp(rr_x,SIG.r)==0){
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
    BN_free(temp_z); 
    BN_free(temp_m); 
    BN_free(temp_rr); 
    BN_free(temp_r);
    BN_free(rr_x);
    BN_free(rr_y);
    EC_POINT_free(G1);
    EC_POINT_free(G2); 
    EC_POINT_free(G3);  

    return Validity;
}