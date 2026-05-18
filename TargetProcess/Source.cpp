#include <Windows.h>
#include <stdio.h>

int main()
{
    DWORD pid = GetCurrentProcessId();
    printf("PID: %lu\n", pid);
    
    int i = 0;
    while (true)
    {
        printf("Processing - %d\n", i++);
        Sleep(1000);
    }
    return 0;
}