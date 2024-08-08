#include "clamav_sec.h"

ModSecValuePair *clamav_handle(request_rec *r, const char *pathfile, const char *pathname, struct cl_engine *engine)
{
    ModSecValuePair *msvp = malloc(sizeof(ModSecValuePair)); // Allocate memory for ModSecValuePair
    if (!msvp)
    {
        fprintf(stderr, "Failed to allocate memory for ModSecValuePair\n");
        return NULL;
    }
    msvp->message = NULL;

    struct cl_scan_options options;


    options.general = CL_DB_STDOPT;

    const char *virname;
    int ret = cl_scanfile(pathfile, &virname, NULL, engine, &options);

    if (ret == CL_VIRUS) {
        msvp->status = 403;
        msvp->message = apr_psprintf(r->pool, "Virus %s found in %s", virname, pathname);

        apr_status_t status = apr_file_remove(pathfile, r->pool);
        if (status != APR_SUCCESS) {
            char error_buf[256];
            apr_strerror(status, error_buf, sizeof(error_buf));
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, "Failed to remove file: %s (%s)", pathfile, error_buf);
        }
    } else if (ret != CL_CLEAN) {
        return NULL;
    } else {
        return NULL;
    }

    // Cleanup ClamAV engine if needed
    // cl_engine_free(engine);
    // OBJ_cleanup();

    return msvp;
}
