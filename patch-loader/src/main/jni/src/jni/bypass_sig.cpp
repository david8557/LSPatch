//
// Created by VIP on 2021/4/25.
//

#include "bypass_sig.h"
#include "elf_util.h"
#include "logging.h"
#include "native_util.h"
#include "patch_loader.h"
#include "utils/hook_helper.hpp"
#include "utils/jni_helper.hpp"

namespace lspd {

    std::string apkPath;
    std::string redirectPath;

    inline static lsplant::Hooker<
            "__openat",
            int(int, const char*, int, int)
    > __openat_ = +[](int fd, const char* pathname, int flag, int mode) {
        if (pathname == apkPath) {
            LOGD("redirect openat");
            return __openat_(fd, redirectPath.c_str(), flag, mode);
        }
        return __openat_(fd, pathname, flag, mode);
    };

    LSP_DEF_NATIVE_METHOD(void, SigBypass, enableOpenatHook, jstring origApkPath, jstring cacheApkPath) {
        // auto sym_openat = SandHook::ElfImg("libc.so").getSymbAddress<void *>("__openat");
        // FIXME: This handle is dynamic and temporarily generated from a special InitInfo.
        auto r = lsplant::HookHandler(lsplant::InitInfo {
                .inline_hooker = [](auto t, auto r) {
                    void *bk = nullptr;
                    return HookFunction(t, r, &bk) == RS_SUCCESS ? bk : nullptr;
                },
                .inline_unhooker = [](auto t) {
                    return UnhookFunction(t) == RT_SUCCESS;
                },
                .art_symbol_resolver = [](auto symbol) {
                    return SandHook::ElfImg("libc.so").getSymbAddress<void *>(symbol);
                },
                .art_symbol_prefix_resolver = [](auto symbol) {
                    return SandHook::ElfImg("libc.so").getSymbPrefixFirstAddress(symbol);
                },
        }).hook(__openat_);
        if (!r) {
            LOGE("Hook __openat fail");
            return;
        }
        lsplant::JUTFString str1(env, origApkPath);
        lsplant::JUTFString str2(env, cacheApkPath);
        apkPath = str1.get();
        redirectPath = str2.get();
        LOGD("apkPath %s", apkPath.c_str());
        LOGD("redirectPath %s", redirectPath.c_str());
    }

    static JNINativeMethod gMethods[] = {
            LSP_NATIVE_METHOD(SigBypass, enableOpenatHook, "(Ljava/lang/String;Ljava/lang/String;)V")
    };

    void RegisterBypass(JNIEnv* env) {
        REGISTER_LSP_NATIVE_METHODS(SigBypass);
    }
}
