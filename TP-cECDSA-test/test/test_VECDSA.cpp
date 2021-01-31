#define DEBUG

#include "../src/VECDSA.hpp"


void test_VECDSA()
{
    cout << "begin the basic correctness test >>>" << endl; 

    VECDSA_PP pp; 
    VECDSA_PP_new(pp); 
    VECDSA_Setup(pp); 

    size_t TEST_NUM = 10000;
    cout << "TEST_NUM ="<< TEST_NUM << endl; 

	auto start_time_dumb = chrono::steady_clock::now(); 
    BIGNUM *aa_1 = BN_new();
    BN_random(aa_1);  

    EC_POINT *AA_1 = EC_POINT_new(group);
    EC_POINT_mul(group, AA_1, aa_1, NULL, NULL, bn_ctx); // K_1 = k_1*G

	auto end_time_dumb = chrono::steady_clock::now(); 
    auto running_time_dumb = end_time_dumb - start_time_dumb;
    cout << "dumb_time = " 
    << chrono::duration <double, milli> (running_time_dumb).count() << " ms" << endl;


    VECDSA_KP keypair[TEST_NUM];
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_KP_new(keypair[i]); 
    }


    
    VECDSA_Randomness Randomness[TEST_NUM];
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_Randomness_new(Randomness[i]); 
    }



    VECDSA_RandomEC RandomEC[TEST_NUM];
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_RandomEC_new(RandomEC[i]); 
    }

    
    VECDSA_SIG SIG[TEST_NUM];
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_SIG_new(SIG[i]);
    }


    VECDSA_B B[TEST_NUM];
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_B_new(B[i]);
    }

    VECDSA_A A[TEST_NUM];
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_A_new(A[i]);
    }
    
    auto start_time_KeyGen_A1 = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_KeyGen_A1(pp, keypair[i], RandomEC[i].K_1);
    }
    auto end_time_KeyGen_A1 = chrono::steady_clock::now(); 
    auto running_time_KeyGen_A1 = end_time_KeyGen_A1 - start_time_KeyGen_A1;
    cout << "running_time_KeyGen_A1 = " 
    << chrono::duration <double, milli> (running_time_KeyGen_A1).count() << " ms" << endl;

    auto start_time_KeyGen_B = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_KeyGen_B(pp, keypair[i], RandomEC[i].K_1, RandomEC[i].K_2);
    }
    auto end_time_KeyGen_B = chrono::steady_clock::now(); 
    auto running_time_KeyGen_B = end_time_KeyGen_B - start_time_KeyGen_B;
    cout << "running_time_KeyGen_B = " 
    << chrono::duration <double, milli> (running_time_KeyGen_B).count() << " ms" << endl;


    auto start_time_KeyGen_A2 = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_KeyGen_A2(pp, keypair[i], RandomEC[i].K_1, RandomEC[i].K_2);
    }
    auto end_time_KeyGen_A2 = chrono::steady_clock::now(); 
    auto running_time_KeyGen_A2 = end_time_KeyGen_A2 - start_time_KeyGen_A2;
    cout << "running_time_KeyGen_A1 = " 
    << chrono::duration <double, milli> (running_time_KeyGen_A2).count() << " ms" << endl;

    auto start_time_KeyGen_A = running_time_KeyGen_A1 + running_time_KeyGen_A2;
    cout << "start_time_KeyGen_A = " 
    << chrono::duration <double, milli> (start_time_KeyGen_A).count() << " ms" << endl;


    auto start_time_offline_A1 = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_offline_A1(pp, Randomness[i].k_1, RandomEC[i].K_1);
    }
    auto end_time_offline_A1 = chrono::steady_clock::now(); 
    auto running_time_offline_A1 = end_time_offline_A1 - start_time_offline_A1;
    cout << "running_time_offline_A1 = " 
    << chrono::duration <double, milli> (running_time_offline_A1).count() << " ms" << endl;


    auto start_time_offline_B = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_offline_B(pp, Randomness[i].k_2, RandomEC[i].K_1, RandomEC[i].K_2, RandomEC[i].K, SIG[i]);
    }
    auto end_time_offline_B = chrono::steady_clock::now(); 
    auto running_time_offline_B = end_time_offline_B - start_time_offline_B;
    cout << "running_time_offline_B = " 
    << chrono::duration <double, milli> (running_time_offline_B).count() << " ms" << endl;


    auto start_time_offline_A2 = chrono::steady_clock::now();
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_offline_A2(pp, Randomness[i].k_1, RandomEC[i].K_2, RandomEC[i].K, SIG[i]);
    }
    auto end_time_offline_A2 = chrono::steady_clock::now(); 
    auto running_time_offline_A2 = end_time_offline_A2 - start_time_offline_A2;
    cout << "running_time_offline_A2 = " 
    << chrono::duration <double, milli> (running_time_offline_A2).count() << " ms" << endl;

    auto running_time_offline_A = running_time_offline_A2 + running_time_offline_A1;
    cout << "running_time_offline_A = " 
    << chrono::duration <double, milli> (running_time_offline_A).count() << " ms" << endl;


    string message = "hahaha";


    auto start_time_Sign_B = chrono::steady_clock::now();
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_Sign_B(pp, SIG[i], keypair[i].sk_2, Randomness[i].k_2, B[i].z_2, message);
    }
    auto end_time_Sign_B = chrono::steady_clock::now(); 
    auto running_time_Sign_B = end_time_Sign_B - start_time_Sign_B;
    cout << "running_time_Sign_B = " 
    << chrono::duration <double, milli> (running_time_Sign_B).count() << " ms" << endl;


    auto start_time_Sign_A = chrono::steady_clock::now();
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_Sign_A(pp,keypair[i].pk_1, keypair[i].pk_2, SIG[i], keypair[i].sk_1, Randomness[i].k_1, B[i].z_2,A[i].z_1, message);
    }
    auto end_time_Sign_A = chrono::steady_clock::now(); 
    auto running_time_Sign_A = end_time_Sign_A - start_time_Sign_A;
    cout << "running_time_Sign_A = " 
    << chrono::duration <double, milli> (running_time_Sign_A).count() << " ms" << endl;
    

    auto start_combiner_time = chrono::steady_clock::now();
    for(auto i = 0; i < TEST_NUM; i++)
    {
    Combiner(pp,keypair[i].pk_1, keypair[i].pk_2, SIG[i], keypair[i].sk_1, Randomness[i].k_1, B[i].z_2,A[i].z_1, message);
    }
    auto end_combiner_time = chrono::steady_clock::now(); 
    auto running_time_combiner = end_combiner_time - start_combiner_time;
    cout << "running_time_combiner = " 
    << chrono::duration <double, milli> (running_time_combiner).count() << " ms" << endl;



    auto start_time_Verf = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    {
    VECDSA_Verify(pp, keypair[i].pk_1, keypair[i].pk_2, message, SIG[i]);
	}
    auto end_time_Verf = chrono::steady_clock::now(); 
    auto running_time_Verf = end_time_Verf - start_time_Verf;
    cout << "verify signature takes time = " 
    << chrono::duration <double, milli> (running_time_Verf).count() << " ms" << endl;
   
}



int main()
{  
    global_initialize(NID_X9_62_prime256v1);   


    SplitLine_print('-'); 
    cout << "VECDSA Signature test begins >>>>>>" << endl; 
    SplitLine_print('-'); 

    test_VECDSA();
    
    SplitLine_print('-'); 
    cout << "VECDSA Signature test finishes <<<<<<" << endl; 
    SplitLine_print('-'); 
  

    global_finalize();

    
    
    return 0; 
}



