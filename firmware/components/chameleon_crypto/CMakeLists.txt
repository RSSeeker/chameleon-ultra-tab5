# ChameleonUltra crypto component (Mifare Classic key recovery)
#
# The Crapto1 sources here are GPL-3.0-or-later and are copied from the
# ChameleonUltra repository (software/src). They are kept as close to upstream
# as possible; see LICENSE and the header of each file.
#
# Tab5 specific files: mfkey32.cpp (mfkey32 + memory accounting) and
# darkside.cpp (the darkside search loop that software/src/darkside.c runs on a
# PC). mfkey.c is a verbatim copy of upstream's darkside cracker core.
#
# src/hardnested/ holds the upstream hardnested cores. They are kept byte for
# byte except for the include block and the threading:
#   - upstream pulls in "../pm3/ui.h" and <Windows.h>, which hardnested_compat.h
#     replaces (the Proxmark3 dependency of these cores is five functions,
#     measured with nm --undefined-only)
#   - hardnested_bruteforce.c spawns one pthread per core; this port runs that
#     same loop on the calling core (num_CPUs() == 1)
#   - hardnested_bruteforce.c's benchmark pair is dropped, since it is the only
#     user of the 507 KB hardnested_benchmark_data.h table.
# hardnested_bitarray_core.c is deliberately absent: it is the bitflip path's
# popcount helper (__popcnt64, x86-only) and the cores here do not call it.

idf_component_register(
    SRCS
        "src/mfkey32.cpp"
        "src/darkside.cpp"
        "src/nested.cpp"
        "src/hardnested/hardnested_bf_core.c"
        "src/hardnested/hardnested_bruteforce.c"
        "src/crapto1.c"
        "src/mfkey.c"
        "src/crypto1.c"
        "src/parity.c"
        "src/bucketsort.c"
    INCLUDE_DIRS
        "include"
    PRIV_INCLUDE_DIRS
        "src"
    REQUIRES
        chameleon
    PRIV_REQUIRES
        heap
        log
        # hardnested_compat.h maps pm3's msclock() onto esp_timer_get_time().
        esp_timer
)
