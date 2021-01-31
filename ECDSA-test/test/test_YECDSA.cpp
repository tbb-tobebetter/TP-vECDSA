#define DEBUG

#include "../src/YECDSA.hpp"

void test_YECDSA()
{
    cout << "begin the basic correctness test >>>" << endl; 
    
    YECDSA_PP pp; 
    YECDSA_PP_new(pp); 
    YECDSA_Setup(pp); 
    
    size_t TEST_NUM = 1000;

    cout << "TEST_NUM= " << TEST_NUM <<endl; 

    auto start_time_dumb = chrono::steady_clock::now(); 
    BIGNUM *kk_1 = BN_new();
    BN_random(kk_1);  

    EC_POINT *KK_1 = EC_POINT_new(group);
    EC_POINT_mul(group, KK_1, kk_1, NULL, NULL, bn_ctx); // K_1 = k_1*G

    auto end_time_dumb = chrono::steady_clock::now(); 
    auto running_time_dumb = end_time_dumb - start_time_dumb;
    cout << "dumb_time = " 
    << chrono::duration <double, milli> (running_time_dumb).count() << " ms" << endl;



    YECDSA_KP keypair[TEST_NUM];
    for(auto i = 0; i < TEST_NUM; i++)
    {
    YECDSA_KP_new(keypair[i]);
    }

    auto start_time = chrono::steady_clock::now();

    for(auto i = 0; i < TEST_NUM; i++)
    {
    YECDSA_KeyGen(pp, keypair[i]); 
    }

    auto end_time = chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    cout << "key generation takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    YECDSA_SIG SIG[TEST_NUM];
    for(auto i = 0; i < TEST_NUM; i++)
    { 
    YECDSA_SIG_new(SIG[i]); 
    }

    YECDSA_Random random[TEST_NUM];
    for(auto i = 0; i < TEST_NUM; i++)
    { 
    YECDSA_Random_new(random[i]); 
    }


    start_time = chrono::steady_clock::now();
    for(auto i = 0; i < TEST_NUM; i++)
    { 
    offline(pp,random[i], SIG[i]);
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "offline takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;


    string message = "hahaha";  

    start_time = chrono::steady_clock::now();
    for(auto i = 0; i < TEST_NUM; i++)
    { 
    YECDSA_Sign(pp, keypair[i].sk, message,random[i], SIG[i]);
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "sign message takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;


    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    { 
    YECDSA_Verify(pp, keypair[i].pk, message, SIG[i]);
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "verify signature takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    }


int main()
{  
    global_initialize(NID_X9_62_prime256v1);   
    //global_initialize(NID_X25519);

    SplitLine_print('-'); 
    cout << "YECDSA Signature test begins >>>>>>" << endl; 
    SplitLine_print('-'); 

    test_YECDSA();

    SplitLine_print('-'); 
    cout << "YECDSA Signature test finishes <<<<<<" << endl; 
    SplitLine_print('-'); 

    global_finalize();
    
    return 0; 
}



