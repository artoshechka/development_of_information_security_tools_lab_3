
#include <Windows.h>
#include <winerror.h>

int main()
{
    // You also specify the complete path.
    LoadLibrary("VirusDLL.dll");
    return 0;
}