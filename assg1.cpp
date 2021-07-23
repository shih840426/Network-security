#include <iostream>
#include <cstdlib>
#include <math.h>
#include <vector>
#include <ctime>
#include <boost/multiprecision/cpp_int.hpp>
#include <random>
#include <string>
#include <stdlib.h>
using namespace std;
using namespace boost::multiprecision;
bool miller_robin(int512_t n,int iter);// miller-robin prime test,若n為質數則為true，否則為false
int512_t mod_exp(int512_t a,int512_t b,int512_t n);// 模冪運算，輸出為a^b modn
int512_t hex2int512(string s);//將字串轉成512bit
string  int5122hex(int512_t num);//將512bits轉成字串
int512_t sqrt_3mod4(int512_t c,int512_t p);//求sqrt in Zp when p=3 mod 4
int512_t sqrt_5mod8(int512_t c,int512_t p);//求sqrt in Zp when p=5 mod 8
int512_t eea(int512_t a, int512_t b, int512_t& x, int512_t& y);//extended Euclid’s algorithm
int main() {
  /*---------------*/
  /*Prime Generator*/
  /*---------------*/
  //C++ 11標準提供之亂數產生器
  cout<<"Prime Generator"<<endl;
  default_random_engine generator( time(NULL) );
  uniform_int_distribution<unsigned int> unif(0, 1);
  int512_t prime_test=0;
  //先隨機產生0或1，並用255個迴圈產生255bits之整數最後一個再乘2加1以確保其為奇數
  for (int i=0;i<255;i++){
    int x = unif(generator);
    prime_test=prime_test*2+x;
  }
  prime_test=prime_test*2+1;
  //先對prime_test做一次miller_robin test,若不是質數則每次減二，其中miller_robin的iteration次數為10次
  while(!miller_robin(prime_test,10)){
    prime_test-=2;
  }
  cout << int5122hex(prime_test) <<endl;
  /*----------------*/
  /*Rabin Encryption*/
  /*----------------*/
  //讀入兩質數及Plain text M，先讀成string再做處理
  cout<<"Rabin Encryption"<<endl;
  string ps,qs,Ms;
  cout << "Enter first prime:" <<endl;
  getline(cin, ps);
  cout << "Enter second prime:" <<endl;
  getline(cin, qs);
  cout << "Enter plaintext:" <<endl;
  getline(cin, Ms);
  //將字串轉為512bits之整數
  int512_t p=hex2int512(ps);
  int512_t q=hex2int512(qs);
  int512_t M=hex2int512(Ms);
  int512_t n=p*q;
  cout << "Public Key n is:" <<int5122hex(n)<<endl;
  //pad為M的最後16個bits
  int512_t pad=M%65536;
  //將M左移16個bits再加上pad即可
  M=M*65536+pad;
  //產生密文c
  int512_t C=(M*M)%n;
  cout << "Ciphertext is:" <<int5122hex(C)<<endl;
  system("pause");
  /*----------------*/
  /*Rabin Decryption*/
  /*----------------*/
  string p2s,q2s,C2s;
  //讀入密文及私鑰
  cout << "Enter Ciphertext:" <<endl;
  getline(cin, C2s);
  cout << "Enter first prime:" <<endl;
  getline(cin, p2s);
  cout << "Enter second prime:" <<endl;
  getline(cin, q2s);
  //將密文及私鑰轉成512int的形式
  int512_t C2=hex2int512(C2s);
  int512_t p2=hex2int512(p2s);
  int512_t q2=hex2int512(q2s);
  int512_t n2=p2*q2;
  int512_t r=0;int512_t s=0;
  //根據不同p求r
  if (p2%4==3)
    r=sqrt_3mod4(C2,p2);
  else if(p2%8==5)
    r=sqrt_5mod8(C2,p2);
  //根據不同q求s
  if (q2%4==3)
    s=sqrt_3mod4(C2,q2);
  else if(q2%8==5)
    s=sqrt_5mod8(C2,q2);
  int512_t c=0;int512_t d=0;//
  //extended Euclid’s algorithm ,cp+dq=1求出c d
  int512_t gcd=eea(p2,q2,c,d);
  //求出x y
  int512_t x=(r*d*q2+s*c*p2)%n2;
  int512_t y=(r*d*q2-s*c*p2+n2)%n2;
  //四個可能的roots
  vector<int512_t> message {x,n2-x,y,n2-y};
  int512_t bits_16;int512_t bits_32;
  int512_t DEC;
  //從四個可能的答案分別檢查
  for(int j=0;j<4;j++){
    bits_16=message[j]%65536;//獲得最後16的bits
    bits_32=(message[j]>>16)%65536;//獲得17~32個bits
    if(bits_16==bits_32){
        DEC=message[j]>>16;//若兩個相等則跳出迴圈
        break;}
  }
  cout << "Plaintext is:" <<int5122hex(DEC)<<endl;

  return 0;
}
bool miller_robin(int512_t n,int iter){
   if(n%2==0) return false;

   int k;
   int512_t m=n-1,y;
   while(m%2==0){
    k++;
    m/=2;
   }//求(n-1)=m*2^k
   for(int j=1;j<=iter;j++){
    default_random_engine generator( time(NULL) );
    uniform_int_distribution<unsigned int> unif(0, 1);
    int512_t a=0;
    for (int i=0;i<256;i++){
    int x =unif(generator);
    a=a*2+x;
  }
    a=a%(n-3)+2;
    /*隨機產生2~n-2之間的整數*/
    y=mod_exp(a,m,n);
    if(y!=1&&y!=n-1){
        int i=1;
        while(i<=k-1&&y!=n-1){
          y=mod_exp(y,2,n);
          if(y==1) {
                return false;
          }
          else{
            i++;
          }
          if(y!=n-1)return false;
        }
    }
    /*參考老師講義的pseudocode*/
   }
  return true;
}
int512_t mod_exp(int512_t a,int512_t b,int512_t n){//計算a^b mod n
    if(n==1) return 0;
    int512_t result=1;
    a=a%n;
    while(b>0){
        if(b%2==1)
            result=(result*a)%n;
        b/=2;
        a=(a*a)%n;
    }
    /*參考wiki的pseudocode*/
    return result;
};
int512_t hex2int512(string s){
    int512_t result=0;
    int bit;
    for(unsigned int i=0;i<s.size();i++){
        if(s[i]=='0'){bit=0;}
        else if(s[i]=='1'){bit=1;}
        else if(s[i]=='2'){bit=2;}
        else if(s[i]=='3'){bit=3;}
        else if(s[i]=='4'){bit=4;}
        else if(s[i]=='5'){bit=5;}
        else if(s[i]=='6'){bit=6;}
        else if(s[i]=='7'){bit=7;}
        else if(s[i]=='8'){bit=8;}
        else if(s[i]=='9'){bit=9;}
        else if(s[i]=='a'){bit=10;}
        else if(s[i]=='b'){bit=11;}
        else if(s[i]=='c'){bit=12;}
        else if(s[i]=='d'){bit=13;}
        else if(s[i]=='e'){bit=14;}
        else if(s[i]=='f'){bit=15;}
        result=result*16+bit;
    }
    return result;
};
string  int5122hex(int512_t num){
    string result;
    int cnt=0;
    while(num!=0){
      cnt++;
      if(cnt>8){
        cnt=1;
        result.insert(0," ");
      }
      int512_t temp=num%16;
      if(temp==0) result.insert(0,"0");
      else if(temp==1) result.insert(0,"1");
      else if(temp==2) result.insert(0,"2");
      else if(temp==3) result.insert(0,"3");
      else if(temp==4) result.insert(0,"4");
      else if(temp==5) result.insert(0,"5");
      else if(temp==6) result.insert(0,"6");
      else if(temp==7) result.insert(0,"7");
      else if(temp==8) result.insert(0,"8");
      else if(temp==9) result.insert(0,"9");
      else if(temp==10) result.insert(0,"a");
      else if(temp==11) result.insert(0,"b");
      else if(temp==12) result.insert(0,"c");
      else if(temp==13) result.insert(0,"d");
      else if(temp==14) result.insert(0,"e");
      else  result.insert(0,"f");
      num/=16;
    }
    return result;
};
int512_t sqrt_3mod4(int512_t c,int512_t p){
  int512_t result;
  result=mod_exp(c,(p+1)/4,p);
  return result;
};
int512_t sqrt_5mod8(int512_t c,int512_t p){
  int512_t result;
  int512_t d=mod_exp(c,(p-1)/4,p);
  if(d==1) result=mod_exp(c,(p+3)/8,p);
  else result=2*c*mod_exp(4*c,(p-5)/8,p)%p;
  return result;
};
int512_t eea(int512_t a, int512_t b, int512_t& x, int512_t& y)//這個函數會產生a及b的gcd並且ax+by+gcd(a,b),有試過用void函數因為我們不需要gcd，但不知道為什麼發生錯誤。
{
    if (a == 0) {
        x = 0;
        y = 1;
        return b;
    }
    int512_t x1, y1;
    int512_t gcd;
    gcd=eea(b%a,a,x1,y1);

    x=y1-(b/a)*x1;
    y=x1;
    return gcd;
}

