#include <cstdio>
#include <cstdlib>
#include <Windows.h>
FILE * trace;

int main(){
	printf("Hello world!\n");
	//HMODULE _h = LoadLibrary("netapi32.dll");

	//if(_h == NULL){
	//	printf("error loading dll\n");
	//}

	//FreeLibrary(_h);
	// system("pause");
	FILE *file = fopen("FlashPlayer.exe", "rb");

	//unsigned char bin[1024];

	//fread(bin, 1024, 1, file);

	//fclose(file);



	return 0;
}