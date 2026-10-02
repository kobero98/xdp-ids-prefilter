#!/bin/bash
# fetch_linux_regex_module.sh — clone the kernel port of Hyperscan used by
# xdp_regex_module at the exact commit of the paper and apply local fixes
# (GFP_ATOMIC allocations from softirq, etc.; see linux-regex-module.patch).
#
# Result: kernel/hs_kfunc/linux-regex-module/   (ignored by git)
# Then, for hscollider (userspace DB compiler):
#   cd linux-regex-module && cmake -B build -DCMAKE_BUILD_TYPE=Release && make -C build -j hscollider
set -e
cd "$(dirname "$0")"
COMMIT=$(cat LINUX_REGEX_MODULE_COMMIT)
[ -d linux-regex-module ] || git clone https://github.com/G-Core/linux-regex-module.git
git -C linux-regex-module checkout -q "$COMMIT"
if git -C linux-regex-module apply --check ../linux-regex-module.patch 2>/dev/null; then
    git -C linux-regex-module apply ../linux-regex-module.patch
    echo "[+] patch applied on $COMMIT"
else
    echo "[=] patch already applied (or tree modified)"
fi
