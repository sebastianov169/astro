// v97fh: MinGW declara nanosleep64 en los headers pero no lo provee en
// ninguna lib de este toolchain (libstdc++ puede referenciarlo). Se define el
// simbolo C directamente (sin incluir el header, para no chocar con su firma).
#if defined(__MINGW32__)
struct timespec;
extern "C" int nanosleep(const struct timespec *req, struct timespec *rem);
extern "C" int nanosleep64(const struct timespec *req, struct timespec *rem)
{
    return nanosleep(req, rem);
}
#endif
