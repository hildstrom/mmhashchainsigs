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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int mmhashchainsigs_init(mmhashchainsigs_worker_t *wrkr)
{
    int rc;
    if (wrkr->inst->cert_path) {
        rc = signer_init_x509(&wrkr->signer,
                              wrkr->inst->privkey_path,
                              wrkr->inst->cert_path);
    } else {
        rc = signer_init(&wrkr->signer,
                         wrkr->inst->privkey_path);
    }
    if (rc != 0) {
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

    if (wrkr->pending_state) {
        mmhashchainsigs_saved_state_t *st = wrkr->pending_state;
        wrkr->pending_state = NULL;
        int ret = mmhashchainsigs_process_final(
            wrkr, st, payload, payload_len,
            sd_buf, sd_buf_len);
        free(st);
        if (wrkr->inst && wrkr->inst->statefiledir) {
            mmhashchainsigs_delete_state(
                wrkr->inst->statefiledir);
        }
        if (ret > 0) {
            return ret;
        }
    }

    if (hashchain_update(&wrkr->chain, payload, payload_len) != 0) {
        return -1;
    }

    uint64_t seq = wrkr->chain.seq - 1;
    int sd_len;

    bool emit_cert = false;
    if (wrkr->is_first) {
        sd_len = hcs_format_sd_init(
            seq, wrkr->chain.current,
            signer_pubkey_fp(&wrkr->signer),
            sd_buf, sd_buf_len);
        wrkr->is_first = 0;
        emit_cert = true;
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

    if (sd_len < 0) {
        return -1;
    }

    /* If embedcert is enabled and this frame opens (or re-opens) a
     * chain, append the cert SD so CA-bundle verifiers can chain-
     * validate without out-of-band cert distribution. The cert SD is
     * NOT part of the hashed payload — verifiers strip it before hashing. */
    if (emit_cert && wrkr->inst->embedcert) {
        const unsigned char *der = NULL;
        int der_len = 0;
        if (signer_get_cert_der(&wrkr->signer, &der, &der_len) == 0) {
            int rem = (int)sd_buf_len - sd_len;
            int n = hcs_format_sd_cert(
                der, (size_t)der_len,
                sd_buf + sd_len, (size_t)rem);
            if (n > 0) {
                sd_len += n;
            }
            /* If formatting fails, fall through: the main SD already
             * succeeded, and the verifier will report a missing-cert
             * error rather than the writer silently producing a half-
             * configured frame. */
        }
    }

    return sd_len;
}

int mmhashchainsigs_final_sign(
    mmhashchainsigs_worker_t *wrkr,
    char *sd_buf, size_t sd_buf_len)
{
    if (!wrkr->initialized || wrkr->chain.msg_count == 0) {
        return 0;
    }

    /* Extend the chain with an empty payload so the final
     * signature is a proper chain entry the verifier can
     * process like any other SIG line. */
    if (hashchain_update(&wrkr->chain, "", 0) != 0) {
        return -1;
    }

    uint64_t seq = wrkr->chain.seq - 1;

    unsigned char sig[HCS_SIG_MAX_LEN];
    size_t sig_len = sizeof(sig);
    if (signer_sign(&wrkr->signer,
                    hashchain_get_current(&wrkr->chain),
                    HCS_HASH_LEN,
                    sig, &sig_len) != 0) {
        return -1;
    }

    int sd_len = hcs_format_sd_sig(
        seq, wrkr->chain.current,
        wrkr->sig_seq_from, seq,
        sig, sig_len,
        sd_buf, sd_buf_len);
    if (sd_len < 0) {
        return -1;
    }

    wrkr->sig_seq_from = seq + 1;
    hashchain_reset_count(&wrkr->chain);
    return sd_len;
}

int mmhashchainsigs_process_final(
    mmhashchainsigs_worker_t *wrkr,
    const mmhashchainsigs_saved_state_t *state,
    const char *payload, size_t payload_len,
    char *sd_buf, size_t sd_buf_len)
{
    if (memcmp(signer_pubkey_fp(&wrkr->signer),
               state->pubkey_fp, HCS_HASH_LEN) != 0) {
        return -2;
    }

    memcpy(wrkr->chain.current,
           state->chain_hash, HCS_HASH_LEN);
    wrkr->chain.seq = state->seq;

    if (hashchain_update(&wrkr->chain,
                         payload, payload_len) != 0) {
        hashchain_init(&wrkr->chain);
        return -1;
    }

    uint64_t seq = wrkr->chain.seq - 1;

    unsigned char sig[HCS_SIG_MAX_LEN];
    size_t sig_len = sizeof(sig);
    if (signer_sign(&wrkr->signer,
                    hashchain_get_current(&wrkr->chain),
                    HCS_HASH_LEN,
                    sig, &sig_len) != 0) {
        hashchain_init(&wrkr->chain);
        return -1;
    }

    int sd_len = hcs_format_sd_sig(
        seq, wrkr->chain.current,
        state->sig_seq_from, seq,
        sig, sig_len,
        sd_buf, sd_buf_len);

    hashchain_init(&wrkr->chain);
    wrkr->is_first = 1;
    wrkr->sig_seq_from = 1;

    return sd_len;
}

#define MMHASHCHAINSIGS_STATE_MAGIC "MMHASHCHAINSIGS_STATE_V1"

int mmhashchainsigs_save_state(
    const mmhashchainsigs_worker_t *wrkr,
    const char *dir)
{
    if (!wrkr->initialized || wrkr->chain.msg_count == 0) {
        return 0;
    }

    char path[512];
    char tmp[512];
    snprintf(path, sizeof(path),
             "%s/" MMHASHCHAINSIGS_STATE_FILE, dir);
    snprintf(tmp, sizeof(tmp),
             "%s/." MMHASHCHAINSIGS_STATE_FILE ".tmp", dir);

    FILE *f = fopen(tmp, "w");
    if (!f) {
        return -1;
    }

    char chain_hex[HCS_HEX_HASH_LEN + 1];
    char fp_hex[HCS_HEX_HASH_LEN + 1];
    hcs_hex_encode(wrkr->chain.current,
                   HCS_HASH_LEN, chain_hex);
    hcs_hex_encode(signer_pubkey_fp(&wrkr->signer),
                   HCS_HASH_LEN, fp_hex);

    fprintf(f,
            MMHASHCHAINSIGS_STATE_MAGIC "\n"
            "chain_hash=%s\n"
            "seq=%lu\n"
            "sig_seq_from=%lu\n"
            "pubkey_fp=%s\n",
            chain_hex,
            (unsigned long)wrkr->chain.seq,
            (unsigned long)wrkr->sig_seq_from,
            fp_hex);

    if (fclose(f) != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 1;
}

mmhashchainsigs_saved_state_t *mmhashchainsigs_load_state(
    const char *dir)
{
    char path[512];
    snprintf(path, sizeof(path),
             "%s/" MMHASHCHAINSIGS_STATE_FILE, dir);

    FILE *f = fopen(path, "r");
    if (!f) {
        return NULL;
    }

    char line[256];
    if (!fgets(line, sizeof(line), f) ||
        strncmp(line, MMHASHCHAINSIGS_STATE_MAGIC,
                strlen(MMHASHCHAINSIGS_STATE_MAGIC)) != 0) {
        fclose(f);
        return NULL;
    }

    mmhashchainsigs_saved_state_t *st =
        calloc(1, sizeof(*st));
    if (!st) {
        fclose(f);
        return NULL;
    }

    int got = 0;
    while (fgets(line, sizeof(line), f)) {
        char val[128];
        unsigned long ul;
        if (sscanf(line, "chain_hash=%64s", val) == 1
            && strlen(val) == HCS_HEX_HASH_LEN) {
            if (hcs_hex_decode(val, HCS_HEX_HASH_LEN,
                    st->chain_hash, HCS_HASH_LEN) == 0) {
                got |= 1;
            }
        } else if (sscanf(line, "seq=%lu", &ul) == 1) {
            st->seq = (uint64_t)ul;
            got |= 2;
        } else if (sscanf(line, "sig_seq_from=%lu",
                           &ul) == 1) {
            st->sig_seq_from = (uint64_t)ul;
            got |= 4;
        } else if (sscanf(line, "pubkey_fp=%64s",
                           val) == 1
                   && strlen(val) == HCS_HEX_HASH_LEN) {
            if (hcs_hex_decode(val, HCS_HEX_HASH_LEN,
                    st->pubkey_fp, HCS_HASH_LEN) == 0) {
                got |= 8;
            }
        }
    }
    fclose(f);

    if (got != 15) {
        free(st);
        return NULL;
    }
    return st;
}

void mmhashchainsigs_delete_state(const char *dir)
{
    char path[512];
    snprintf(path, sizeof(path),
             "%s/" MMHASHCHAINSIGS_STATE_FILE, dir);
    unlink(path);
}

void mmhashchainsigs_free(mmhashchainsigs_worker_t *wrkr)
{
    if (wrkr->initialized) {
        signer_free(&wrkr->signer);
        wrkr->initialized = 0;
    }
    free(wrkr->pending_state);
    wrkr->pending_state = NULL;
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
    unsigned int wrkr_count;
} instanceData;

typedef struct wrkrInstanceData {
    instanceData *pData;
    mmhashchainsigs_worker_t wrkr;
} wrkrInstanceData_t;

static struct cnfparamdescr actpdescr[] = {
    { "privatekey",    eCmdHdlrString,      CNFPARAM_REQUIRED },
    { "certificate",   eCmdHdlrString,      0 },
    { "embedcert",     eCmdHdlrBinary,      0 },
    { "template",      eCmdHdlrString,      0 },
    { "signinterval",  eCmdHdlrPositiveInt,  0 },
    { "statefiledir",  eCmdHdlrString,      0 },
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
    pWrkrData->pData->wrkr_count++;
    if (pWrkrData->pData->wrkr_count > 1) {
        LogError(0, RS_RET_ERR,
                 "mmhashchainsigs: multiple worker threads"
                 " are not supported — the hash chain"
                 " requires sequential processing."
                 " Set queue.workerThreads=\"1\" on this"
                 " action.");
        iRet = RS_RET_ERR;
    } else {
        pWrkrData->wrkr.inst = &pWrkrData->pData->inst;
        pWrkrData->wrkr.initialized = 0;
        pWrkrData->wrkr.pending_state = NULL;
        if (pWrkrData->pData->inst.statefiledir) {
            pWrkrData->wrkr.pending_state =
                mmhashchainsigs_load_state(
                    pWrkrData->pData->inst.statefiledir);
        }
    }
ENDcreateWrkrInstance

BEGINfreeInstance
CODESTARTfreeInstance
    free(pData->inst.privkey_path);
    free(pData->inst.cert_path);
    free(pData->inst.tpl_name);
    free(pData->inst.statefiledir);
ENDfreeInstance

BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
    if (pWrkrData->pData->inst.statefiledir) {
        mmhashchainsigs_save_state(
            &pWrkrData->wrkr,
            pWrkrData->pData->inst.statefiledir);
    }
    mmhashchainsigs_free(&pWrkrData->wrkr);
    if (pWrkrData->pData->wrkr_count > 0) {
        pWrkrData->pData->wrkr_count--;
    }
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
                           "certificate")) {
            pData->inst.cert_path =
                (char *)es_str2cstr(pvals[i].val.d.estr,
                                    NULL);
        } else if (!strcmp(actpblk.descr[i].name,
                           "embedcert")) {
            pData->inst.embedcert = (int)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name,
                           "template")) {
            pData->inst.tpl_name =
                (char *)es_str2cstr(pvals[i].val.d.estr,
                                    NULL);
        } else if (!strcmp(actpblk.descr[i].name,
                           "signinterval")) {
            pData->inst.sign_interval =
                (unsigned int)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name,
                           "statefiledir")) {
            pData->inst.statefiledir =
                (char *)es_str2cstr(pvals[i].val.d.estr,
                                    NULL);
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

    char sd[HCS_SD_WITH_CERT_MAX_LEN];
    int sd_len = mmhashchainsigs_process_msg(
        &pWrkrData->wrkr, payload, payload_len,
        sd, sizeof(sd));
    if (sd_len < 0) {
        ABORT_FINALIZE(RS_RET_SUSPENDED);
    }

    /* Output SD section: mmhashchainsigs SD || cleaned_SD
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
