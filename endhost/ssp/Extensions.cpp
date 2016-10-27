/* Copyright 2016 ETH Zurich
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <arpa/inet.h>
#include <stdio.h>

#include "Extensions.h"
#include "Utils.h"

uint8_t * parseExtensions(SCIONHeader *sh, uint8_t *ptr)
{
    SCIONCommonHeader *sch = &sh->commonHeader;
    uint8_t nextHeader = sch->next_header;
    uint8_t currHeader = nextHeader;
    uint8_t headerLen = sch->header_len;
    uint8_t type = 0;
    while (!is_known_proto(currHeader)) {
        nextHeader = *ptr++;
        headerLen = *ptr++;
        type = *ptr++;
        uint8_t realLen = (headerLen + 1) * SCION_EXT_LINE;
        SCIONExtension *ext = (SCIONExtension *)malloc(sizeof(SCIONExtension));
        memset(ext, 0, sizeof(SCIONExtension));
        ext->nextHeader = nextHeader;
        ext->headerLen = headerLen;
        ext->type = type;
        ext->extClass = currHeader;
        ext->data = malloc(realLen - SCION_EXT_SUBHDR);
        memcpy(ext->data, ptr, realLen - SCION_EXT_SUBHDR);
        currHeader = nextHeader;
        ptr += realLen - SCION_EXT_SUBHDR;

        if (sh->extensions == NULL) {
            sh->extensions = ext;
        } else {
            SCIONExtension *se = sh->extensions;
            while (se->nextExt != NULL)
                se = se->nextExt;
            se->nextExt = ext;
        }
        sh->numExtensions++;
    }
    return ptr;
}

uint8_t * packExtensions(SCIONHeader *sh, uint8_t *ptr)
{
    SCIONExtension *ext = sh->extensions;
    while (ext != NULL) {
        if (ext->extClass == HOP_BY_HOP) {
        } else {
            switch (ext->type) {
            case PATH_PROBE:
                ptr = packProbeExtension(ext, ptr);
                break;
            default:
                break;
            }
        }
        ext = ext->nextExt;
    }
    return ptr;
}

uint8_t * packSubheader(SCIONExtension *ext, uint8_t *ptr)
{
    *ptr++ = ext->nextHeader;
    *ptr++ = ext->headerLen;
    *ptr++ = ext->type;
    return ptr;
}

void addProbeExtension(SCIONHeader *sh, uint32_t probeNum, uint8_t ack)
{
    SCIONCommonHeader *sch = &sh->commonHeader;
    SCIONExtension *ext = (SCIONExtension *)malloc(sizeof(SCIONExtension));
    memset(ext, 0, sizeof(SCIONExtension));
    ext->type = PATH_PROBE;
    ext->extClass = END_TO_END;
    ext->data = malloc(5);
    *(uint8_t *)ext->data = ack;
    setProbeNum(ext, probeNum);
    SCIONExtension *se = sh->extensions;
    if (se == NULL) {
        sh->extensions = ext;
        ext->nextHeader = sch->next_header;
        sch->next_header = ext->extClass;
    } else {
        while (se->nextExt != NULL)
            se = se->nextExt;
        se->nextExt = ext;
        ext->nextHeader = se->nextHeader;
        se->nextHeader = ext->extClass;
    }
    sh->numExtensions++;
}

uint8_t * packProbeExtension(SCIONExtension *ext, uint8_t *ptr)
{
    ptr = packSubheader(ext, ptr);
    *ptr++ = *(uint8_t *)ext->data;
    *(uint32_t *)ptr = htonl(getProbeNum(ext));
    ptr += 4;
    return ptr;
}

SCIONExtension * findProbeExtension(SCIONHeader *sh)
{
    SCIONExtension *ext = sh->extensions;
    while (ext != NULL) {
        if (ext->type == PATH_PROBE && ext->extClass == END_TO_END)
            return ext;
        ext = ext->nextExt;
    }
    return NULL;
}
