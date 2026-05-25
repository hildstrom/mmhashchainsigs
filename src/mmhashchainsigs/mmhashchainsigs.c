/*
 * mmhashchainsigs.c - Rsyslog message modification module for signed logging
 *
 * Enriches syslog messages with RFC 5424 structured data (SD)
 * containing SHA-256 hash chain metadata and periodic Ed25519
 * signatures. Designed for RELP pipelines where the origin signs
 * messages before transmission.
 *
 * The standalone core (above the #ifndef MMHASHCHAINSIGS_STANDALONE guard)
 * is independent of rsyslog and can be tested without rsyslog headers.
 */
#include "mmhashchainsigs.h"

int mmhashchainsigs_init(mmhashchainsigs_worker_t *wrkr)
{
    if (signer_init(&wrkr->signer,
                    wrkr->inst->privkey_path) != 0) {
        return -1;
    }
    if (hashchain_init(&wrkr->chain) != 0) {
        signer_free(&wrkr->signer);
        return -1;
    }
    wrkr->sig_seq_from = 1;
    wrkr->initialized = 1;
    wrkr->is_first = 1;
    return 0;
}

int mmhashchainsigs_process_msg(
    mmhashchainsigs_worker_t *wrkr,
    const char *payload, size_t payload_len,
    char *sd_buf, size_t sd_buf_len)
{
    if (!wrkr->initialized) {
        if (mmhashchainsigs_init(wrkr) != 0) {
            return -1;
        }
    }

    if (hashchain_update(&wrkr->chain, payload, payload_len) != 0) {
        return -1;
    }

    uint64_t seq = wrkr->chain.seq - 1;
    int sd_len;

    if (wrkr->is_first) {
        sd_len = hcs_format_sd_init(
            seq, wrkr->chain.current,
            signer_pubkey_fp(&wrkr->signer),
            sd_buf, sd_buf_len);
        wrkr->is_first = 0;
    } else if (wrkr->chain.msg_count
               >= wrkr->inst->sign_interval) {
        unsigned char sig[HCS_SIG_MAX_LEN];
        size_t sig_len = sizeof(sig);
        if (signer_sign(&wrkr->signer,
                        hashchain_get_current(&wrkr->chain),
                        HCS_HASH_LEN,
                        sig, &sig_len) != 0) {
            return -1;
        }
        sd_len = hcs_format_sd_sig(
            seq, wrkr->chain.current,
            wrkr->sig_seq_from, seq,
            sig, sig_len,
            sd_buf, sd_buf_len);
        wrkr->sig_seq_from = seq + 1;
        hashchain_reset_count(&wrkr->chain);
    } else {
        sd_len = hcs_format_sd_msg(
            seq, wrkr->chain.current,
            sd_buf, sd_buf_len);
    }

    return sd_len;
}

void mmhashchainsigs_free(mmhashchainsigs_worker_t *wrkr)
{
    if (wrkr->initialized) {
        signer_free(&wrkr->signer);
        wrkr->initialized = 0;
    }
}

/*
 * ================================================================
 * Rsyslog module boilerplate
 *
 * The section below requires rsyslog development headers.
 * When building without rsyslog headers (e.g., for standalone
 * testing), define MMHASHCHAINSIGS_STANDALONE to skip this section.
 * ================================================================
 */
#ifndef MMHASHCHAINSIGS_STANDALONE

#include "rsyslog.h"
#include "conf.h"
#include "syslogd-types.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "cfsysline.h"
#include "msg.h"
#include "stringbuf.h"

#include <stdio.h>
#include <string.h>

/*
 * getMSGID is static inside rsyslog's msg.c, but pCSMSGID is public on
 * smsg_t. Reproduce the trivial lookup here so we can read the field
 * without pulling in template-engine plumbing.
 */
static const char *get_msgid_str(smsg_t *pM)
{
    if (pM == NULL || pM->pCSMSGID == NULL) return "-";
    return (const char *)rsCStrGetSzStrNoNULL(pM->pCSMSGID);
}

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("mmhashchainsigs")
DEF_OMOD_STATIC_DATA

struct modConfData_s {
    rsconf_t *pConf;
};
static modConfData_t *runModConf = NULL;

typedef struct _instanceData {
    mmhashchainsigs_instance_t inst;
} instanceData;

typedef struct wrkrInstanceData {
    instanceData *pData;
    mmhashchainsigs_worker_t wrkr;
} wrkrInstanceData_t;

static struct cnfparamdescr actpdescr[] = {
    { "privatekey",   eCmdHdlrString,      CNFPARAM_REQUIRED },
    { "template",     eCmdHdlrString,      0 },
    { "signinterval", eCmdHdlrPositiveInt,  0 },
};
static struct cnfparamblk actpblk = {
    CNFPARAMBLK_VERSION,
    sizeof(actpdescr) / sizeof(struct cnfparamdescr),
    actpdescr
};

BEGINcreateInstance
CODESTARTcreateInstance
    pData->inst.sign_interval = MMHASHCHAINSIGS_DEFAULT_SIGN_INTERVAL;
ENDcreateInstance

BEGINcreateWrkrInstance
CODESTARTcreateWrkrInstance
    pWrkrData->wrkr.inst = &pWrkrData->pData->inst;
    pWrkrData->wrkr.initialized = 0;
ENDcreateWrkrInstance

BEGINfreeInstance
CODESTARTfreeInstance
    free(pData->inst.privkey_path);
    free(pData->inst.tpl_name);
ENDfreeInstance

BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
    mmhashchainsigs_free(&pWrkrData->wrkr);
ENDfreeWrkrInstance

BEGINnewActInst
    struct cnfparamvals *pvals = NULL;
CODESTARTnewActInst
    pvals = nvlstGetParams(lst, &actpblk, NULL);
    if (pvals == NULL) {
        LogError(0, RS_RET_MISSING_CNFPARAMS,
                 "mmhashchainsigs: missing required parameters");
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }

    CODE_STD_STRING_REQUESTnewActInst(1)

    CHKiRet(createInstance(&pData));

    for (int i = 0; i < actpblk.nParams; i++) {
        if (!pvals[i].bUsed) continue;

        if (!strcmp(actpblk.descr[i].name, "privatekey")) {
            pData->inst.privkey_path =
                (char *)es_str2cstr(pvals[i].val.d.estr,
                                    NULL);
        } else if (!strcmp(actpblk.descr[i].name,
                           "template")) {
            pData->inst.tpl_name =
                (char *)es_str2cstr(pvals[i].val.d.estr,
                                    NULL);
        } else if (!strcmp(actpblk.descr[i].name,
                           "signinterval")) {
            pData->inst.sign_interval =
                (unsigned int)pvals[i].val.d.n;
        }
    }

    CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));

CODE_STD_FINALIZERnewActInst
    cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst

BEGINdoAction_NoStrings
    smsg_t **ppMsg = (smsg_t **)pMsgData;
    smsg_t *pMsg = ppMsg[0];
    char *cleaned_sd = NULL;
    char *payload = NULL;
    char *new_sd = NULL;
CODESTARTdoAction
    const char *msg = (const char *)getMSG(pMsg);
    size_t msg_len = (size_t)getMSGLen(pMsg);

    /* Capture the six syslog header fields at the signing point so
     * the chain protects them too. They travel as a separate SD
     * element (HCS_SD_HDR_ID) that becomes part of the hashed payload
     * (the verifier strips only HCS_SD_ID before hashing). */
    /* Ask rsyslog for the reported time in RFC 3339 form. getTimeReported
     * handles locking, lazy caching, and parser-version differences. */
    const char *ts_buf = getTimeReported(pMsg, tplFmtRFC3339Date);
    if (ts_buf == NULL) ts_buf = "-";
    unsigned int pri = (unsigned int)getPRIi(pMsg);
    const char *host_s   = (const char *)getHOSTNAME(pMsg);
    const char *app_s    = (const char *)getAPPNAME(pMsg, LOCK_MUTEX);
    const char *procid_s = (const char *)getPROCID(pMsg, LOCK_MUTEX);
    const char *msgid_s  = get_msgid_str(pMsg);

    char hdr_sd[HCS_SD_HDR_MAX_LEN];
    int hdr_len = hcs_format_sd_hdr(
        pri, ts_buf, host_s, app_s, procid_s, msgid_s,
        hdr_sd, sizeof(hdr_sd));
    if (hdr_len < 0) {
        ABORT_FINALIZE(RS_RET_SUSPENDED);
    }

    uchar *cur_sd_buf = NULL;
    rs_size_t cur_sd_len = 0;
    MsgGetStructuredData(pMsg, &cur_sd_buf, &cur_sd_len);
    size_t cur_len = 0;
    if (cur_sd_buf && cur_sd_len > 0
        && !(cur_sd_len == 1 && cur_sd_buf[0] == '-')) {
        cur_len = (size_t)cur_sd_len;
    }

    /* Strip any client-supplied element with either of our SD-IDs.
     * mmhashchainsigs is the trusted signer; client elements with our
     * IDs are not authoritative and would also collide with the
     * elements we add (RFC 5424 §6.3.2 requires SD-ID uniqueness). */
    size_t stripped_len = 0;
    char *stripped_sd = NULL;
    if (cur_len > 0) {
        stripped_sd = malloc(cur_len + 1);
        if (!stripped_sd) {
            ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
        }
        int n = hcs_strip_all_sd(
            (const char *)cur_sd_buf, cur_len,
            HCS_SD_ID,
            stripped_sd, cur_len + 1, NULL);
        if (n < 0) {
            free(stripped_sd);
            ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
        }
        /* Strip in place: src and out overlap; safe because we only
         * ever copy chars forward by the same amount as we read. */
        n = hcs_strip_all_sd(
            stripped_sd, (size_t)n,
            HCS_SD_HDR_ID,
            stripped_sd, cur_len + 1, NULL);
        if (n < 0) {
            free(stripped_sd);
            ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
        }
        stripped_len = (size_t)n;
    }

    /* cleaned_sd = hdr_SD || stripped_client_SD. This is the
     * "non-self" SD section that the verifier will hash. */
    size_t cleaned_len = (size_t)hdr_len + stripped_len;
    cleaned_sd = malloc(cleaned_len + 1);
    if (!cleaned_sd) {
        free(stripped_sd);
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
    memcpy(cleaned_sd, hdr_sd, (size_t)hdr_len);
    if (stripped_len > 0) {
        memcpy(cleaned_sd + hdr_len, stripped_sd, stripped_len);
    }
    free(stripped_sd);
    stripped_sd = NULL;

    /* Hash input is cleaned_SD || MSG. The verifier strips only the
     * leading [mmhashchainsigs@32473 ...] element from the stored
     * line, so what it hashes is exactly these bytes. */
    size_t payload_len = cleaned_len + msg_len;
    payload = malloc(payload_len > 0 ? payload_len : 1);
    if (!payload) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
    memcpy(payload, cleaned_sd, cleaned_len);
    if (msg_len > 0) {
        memcpy(payload + cleaned_len, msg, msg_len);
    }

    char sd[HCS_SD_MAX_LEN];
    int sd_len = mmhashchainsigs_process_msg(
        &pWrkrData->wrkr, payload, payload_len,
        sd, sizeof(sd));
    if (sd_len < 0) {
        ABORT_FINALIZE(RS_RET_SUSPENDED);
    }

    /* Output SD section: siglog SD || cleaned_SD
     * (cleaned_SD already starts with the hdr element). */
    size_t new_len = (size_t)sd_len + cleaned_len;
    new_sd = malloc(new_len + 1);
    if (!new_sd) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
    memcpy(new_sd, sd, (size_t)sd_len);
    memcpy(new_sd + sd_len, cleaned_sd, cleaned_len);
    new_sd[new_len] = '\0';

    MsgSetStructuredData(pMsg, new_sd);

finalize_it:
    free(cleaned_sd);
    free(payload);
    free(new_sd);
ENDdoAction

BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
ENDisCompatibleWithFeature

BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
ENDdbgPrintInstInfo

BEGINtryResume
CODESTARTtryResume
ENDtryResume

NO_LEGACY_CONF_parseSelectorAct

BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
ENDbeginCnfLoad

BEGINendCnfLoad
CODESTARTendCnfLoad
ENDendCnfLoad

BEGINcheckCnf
CODESTARTcheckCnf
ENDcheckCnf

BEGINactivateCnf
CODESTARTactivateCnf
ENDactivateCnf

BEGINfreeCnf
CODESTARTfreeCnf
ENDfreeCnf

BEGINmodExit
CODESTARTmodExit
ENDmodExit

BEGINqueryEtryPt
CODESTARTqueryEtryPt
    CODEqueryEtryPt_STD_OMOD_QUERIES
    CODEqueryEtryPt_STD_OMOD8_QUERIES
    CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
    CODEqueryEtryPt_STD_CONF2_QUERIES
ENDqueryEtryPt

BEGINmodInit()
CODESTARTmodInit
    *ipIFVersProvided = CURR_MOD_IF_VERSION;
CODEmodInit_QueryRegCFSLineHdlr
ENDmodInit

#endif /* MMHASHCHAINSIGS_STANDALONE */
