/// @file VirusDLL/Source.cpp
/// @brief Внедряемая DLL. При загрузке в чужой процесс показывает MessageBox
///        с именем процесса-жертвы в заголовке.

#include <Windows.h>
#include <psapi.h>
#include <winerror.h>

/// @brief Полезная нагрузка, выполняемая при инъекции.
///        Получает имя текущего процесса и отображает диалоговое окно.
void Attack()
{
    char szProcessName[128];
    GetModuleBaseNameA(GetCurrentProcess(), NULL, szProcessName, sizeof(szProcessName));
    MessageBoxA(NULL, "BOOM!", szProcessName, MB_OK);
}

/// @brief Точка входа DLL.
/// @param hinstDLL   Дескриптор модуля DLL.
/// @param fdwReason  Причина вызова (DLL_PROCESS_ATTACH и др.).
/// @param lpvReserved Зарезервировано системой.
/// @return TRUE при успехе.
BOOL WINAPI DllMain(HINSTANCE hinstDLL,  // дескриптор модуля DLL
                    DWORD fdwReason,     // причина вызова
                    LPVOID lpvReserved)  // зарезервировано
{
    // Выполняем действия в зависимости от причины вызова.
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // Инициализация при первой загрузке DLL в процесс.
            Attack();
            // Вернуть FALSE, чтобы отменить загрузку DLL.
            break;

        case DLL_THREAD_ATTACH:
            // Инициализация для каждого нового потока.
            break;

        case DLL_THREAD_DETACH:
            // Очистка ресурсов потока при его завершении.
            break;

        case DLL_PROCESS_DETACH:

            if (lpvReserved != nullptr)
            {
                break;  // процесс завершается — очистка не нужна
            }

            // Очистка ресурсов DLL при выгрузке из процесса.
            break;
    }
    return TRUE;  // DLL_PROCESS_ATTACH обработан успешно.
}
