/*
 * This file is part of LSPosed.
 *
 * LSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2021 - 2022 LSPosed Contributors
 */

#ifndef LSPATCH_OAT_FILE_MANAGER_H
#define LSPATCH_OAT_FILE_MANAGER_H

#include "context.h"
#include "utils/hook_helper.hpp"

using namespace lsplant;

namespace art {
    inline static Hooker<
            "_ZN3art14OatFileManager25RunBackgroundVerificationERKNSt3__16vectorIPKNS_7DexFileENS1_9allocatorIS5_EEEEP8_jobjectPKc",
            void(void*, const std::vector<const void *> &, jobject, const char *)
    > RunBackgroundVerificationWithContext_ =
            +[](void* thiz, const std::vector<const void *> &dex_files,
                jobject class_loader,
                const char *class_loader_context) -> void {
                if (lspd::Context::GetInstance()->GetCurrentClassLoader() == nullptr) {
                    LOGD("Disabled background verification");
                    return;
                }
                RunBackgroundVerificationWithContext_(thiz, dex_files, class_loader, class_loader_context);
            };

    inline static Hooker<
            "_ZN3art14OatFileManager25RunBackgroundVerificationERKNSt3__16vectorIPKNS_7DexFileENS1_9allocatorIS5_EEEEP8_jobject",
            void(void*, const std::vector<const void *> &, jobject)
    > RunBackgroundVerification_ =
            +[](void* thiz, const std::vector<const void *> &dex_files,
                jobject class_loader) -> void {
                if (lspd::Context::GetInstance()->GetCurrentClassLoader() == nullptr) {
                    LOGD("Disabled background verification");
                    return;
                }
                RunBackgroundVerification_(thiz, dex_files, class_loader);
            };


    static void DisableBackgroundVerification(const lsplant::HookHandler &handler) {
        const int api_level = lspd::GetAndroidApiLevel();
        if (api_level >= __ANDROID_API_Q__) {
            handler.hook(RunBackgroundVerificationWithContext_, RunBackgroundVerification_);
        }
    }
}


#endif //LSPATCH_OAT_FILE_MANAGER_H
