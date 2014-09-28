#include <crypto/testutils/test_data.hh>

#include <unistd.h>

namespace crypto {

#ifdef __linux__
#include <linux/limits.h>
std::string test_data_path(std::string test_data_file) {
    char buffer[PATH_MAX];
    ssize_t retval;

    retval = readlink("/proc/self/exe", buffer, sizeof(buffer));
    if (retval < 0) {
        return "";
    }

    std::string exe_path(buffer, retval);
    size_t slash_pos = exe_path.find_last_of('/');
    if (slash_pos == std::string::npos) {
        return "";
    }

    return exe_path.substr(0, slash_pos + 1) + test_data_file;
}
#else
#error   "Non-Linux test data location is not implemented"
#endif  /* __LINUX__ */

}
