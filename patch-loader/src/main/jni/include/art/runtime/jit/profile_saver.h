//
// Created by loves on 6/19/2021.
//

#ifndef LSPATCH_PROFILE_SAVER_H
#define LSPATCH_PROFILE_SAVER_H

#include "utils/hook_helper.hpp"

using namespace lsplant;

namespace art {
    inline static Hooker<
            "_ZN3art12ProfileSaver20ProcessProfilingInfoEbPt",
            bool(void*, bool, uint16_t *)
    > ProcessProfilingInfo_ = +[](void* thiz, bool, uint16_t *) -> bool {
        LOGD("skipped profile saving");
        return true;
    };

    inline static Hooker<
            "_ZN3art12ProfileSaver20ProcessProfilingInfoEbbPt",
            bool(void*, bool, bool, uint16_t *)
    > ProcessProfilingInfoWithBool_ = +[](void* thiz, bool, bool, uint16_t *) -> bool {
        LOGD("skipped profile saving");
        return true;
    };

    inline static Hooker<
            "execve",
            int(const char*, const char*[], char* const[])
    > execve_ = +[](const char *pathname, const char *argv[], char *const envp[]) {
        if (strstr(pathname, "dex2oat")) {
            size_t count = 0;
            while (argv[count++] != nullptr);
            std::unique_ptr<const char *[]> new_args = std::make_unique<const char *[]>(
                    count + 1);
            for (size_t i = 0; i < count - 1; ++i)
                new_args[i] = argv[i];
            new_args[count - 1] = "--inline-max-code-units=0";
            new_args[count] = nullptr;

            LOGD("dex2oat by disable inline!");
            int ret = execve_(pathname, new_args.get(), envp);
            return ret;
        }
        int ret = execve_(pathname, argv, envp);
        return ret;
    };

    static void DisableInline(const HookHandler &handler) {
        handler.hook(ProcessProfilingInfo_, ProcessProfilingInfoWithBool_);
        handler.hook(execve_);
    }
}


#endif //LSPATCH_PROFILE_SAVER_H
