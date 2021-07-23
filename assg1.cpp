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
bool miller_robin(int512_t n,int iter);// miller-robin prime test,�Yn����ƫh��true�A�_�h��false
int512_t mod_exp(int512_t a,int512_t b,int512_t n);// �Ҿ��B��A��X��a^b modn
int512_t hex2int512(string s);//�N�r���ন512bit
string  int5122hex(int512_t num);//�N512bits�ন�r��
int512_t sqrt_3mod4(int512_t c,int512_t p);//�Dsqrt in Zp when p=3 mod 4
int512_t sqrt_5mod8(int512_t c,int512_t p);//�Dsqrt in Zp when p=5 mod 8
int512_t eea(int512_t a, int512_t b, int512_t& x, int512_t& y);//extended Euclid��s algorithm
int main() {
  /*---------------*/
  /*Prime Generator*/
  /*---------------*/
  //C++ 11�зǴ��Ѥ��üƲ��;�
  cout<<"Prime Generator"<<endl;
  default_random_engine generator( time(NULL) );
  uniform_int_distribution<unsigned int> unif(0, 1);
  int512_t prime_test=0;
  //���H������0��1�A�å�255�Ӱj�鲣��255bits����Ƴ̫�@�ӦA��2�[1�H�T�O�䬰�_��
  for (int i=0;i<255;i++){
    int x = unif(generator);
    prime_test=prime_test*2+x;
  }
  prime_test=prime_test*2+1;
  //����prime_test���@��miller_robin test,�Y���O��ƫh�C����G�A�䤤miller_robin��iteration���Ƭ�10��
  while(!miller_robin(prime_test,10)){
    prime_test-=2;
  }
  cout << int5122hex(prime_test) <<endl;
  /*----------------*/
  /*Rabin Encryption*/
  /*----------------*/
  //Ū�J���Ƥ�Plain text M�A��Ū��string�A���B�z
  cout<<"Rabin Encryption"<<endl;
  string ps,qs,Ms;
  cout << "Enter first prime:" <<endl;
  getline(cin, ps);
  cout << "Enter second prime:" <<endl;
  getline(cin, qs);
  cout << "Enter plaintext:" <<endl;
  getline(cin, Ms);
  //�N�r���ର512bits�����
  int512_t p=hex2int512(ps);
  int512_t q=hex2int512(qs);
  int512_t M=hex2int512(Ms);
  int512_t n=p*q;
  cout << "Public Key n is:" <<int5122hex(n)<<endl;
  //pad��M���̫�16��bits
  int512_t pad=M%65536;
  //�NM����16��bits�A�[�Wpad�Y�i
  M=M*65536+pad;
  //���ͱK��c
  int512_t C=(M*M)%n;
  cout << "Ciphertext is:" <<int5122hex(C)<<endl;
  system("pause");
  /*----------------*/
  /*Rabin Decryption*/
  /*----------------*/
  string p2s,q2s,C2s;
  //Ū�J�K��Ψp�_
  cout << "Enter Ciphertext:" <<endl;
  getline(cin, C2s);
  cout << "Enter first prime:" <<endl;
  getline(cin, p2s);
  cout << "Enter second prime:" <<endl;
  getline(cin, q2s);
  //�N�K��Ψp�_�ন512int���Φ�
  int512_t C2=hex2int512(C2s);
  int512_t p2=hex2int512(p2s);
  int512_t q2=hex2int512(q2s);
  int512_t n2=p2*q2;
  int512_t r=0;int512_t s=0;
  //�ھڤ��Pp�Dr
  if (p2%4==3)
    r=sqrt_3mod4(C2,p2);
  else if(p2%8==5)
    r=sqrt_5mod8(C2,p2);
  //�ھڤ��Pq�Ds
  if (q2%4==3)
    s=sqrt_3mod4(C2,q2);
  else if(q2%8==5)
    s=sqrt_5mod8(C2,q2);
  int512_t c=0;int512_t d=0;//
  //extended Euclid��s algorithm ,cp+dq=1�D�Xc d
  int512_t gcd=eea(p2,q2,c,d);
  //�D�Xx y
  int512_t x=(r*d*q2+s*c*p2)%n2;
  int512_t y=(r*d*q2-s*c*p2+n2)%n2;
  //�|�ӥi�઺roots
  vector<int512_t> message {x,n2-x,y,n2-y};
  int512_t bits_16;int512_t bits_32;
  int512_t DEC;
  //�q�|�ӥi�઺���פ��O�ˬd
  for(int j=0;j<4;j++){
    bits_16=message[j]%65536;//��o�̫�16��bits
    bits_32=(message[j]>>16)%65536;//��o17~32��bits
    if(bits_16==bits_32){
        DEC=message[j]>>16;//�Y��Ӭ۵��h���X�j��
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
   }//�D(n-1)=m*2^k
   for(int j=1;j<=iter;j++){
    default_random_engine generator( time(NULL) );
    uniform_int_distribution<unsigned int> unif(0, 1);
    int512_t a=0;
    for (int i=0;i<256;i++){
    int x =unif(generator);
    a=a*2+x;
  }
    a=a%(n-3)+2;
    /*�H������2~n-2���������*/
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
    /*�ѦҦѮv���q��pseudocode*/
   }
  return true;
}
int512_t mod_exp(int512_t a,int512_t b,int512_t n){//�p��a^b mod n
    if(n==1) return 0;
    int512_t result=1;
    a=a%n;
    while(b>0){
        if(b%2==1)
            result=(result*a)%n;
        b/=2;
        a=(a*a)%n;
    }
    /*�Ѧ�wiki��pseudocode*/
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
int512_t eea(int512_t a, int512_t b, int512_t& x, int512_t& y)//�o�Ө�Ʒ|����a��b��gcd�åBax+by+gcd(a,b),���չL��void��Ʀ]���ڭ̤��ݭngcd�A�������D������o�Ϳ��~�C
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

