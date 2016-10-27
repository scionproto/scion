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

#ifndef EXTENSIONS_H
#define EXTENSIONS_H

#include "DataStructures.h"
#include "SCIONDefines.h"

// Extensions
#define SCION_EXT_LINE LINE_LEN
#define SCION_EXT_SUBHDR 3

#define HOP_BY_HOP 0
#define END_TO_END 222

#define TRACEROUTE 0
#define SIBRA 1

#define PATH_TRANSPORT 0
#define PATH_PROBE 1

uint8_t * parseExtensions(SCIONHeader *sh, uint8_t *ptr);
uint8_t * packSubheader(SCIONExtension *ext, uint8_t *ptr);
uint8_t * packExtensions(SCIONHeader *sh, uint8_t *ptr);
void addProbeExtension(SCIONHeader *sh, uint32_t probeNum, uint8_t ack);
uint8_t * packProbeExtension(SCIONExtension *ext, uint8_t *ptr);
SCIONExtension * findProbeExtension(SCIONHeader *sh);

#define getProbeNum(ext) (*(uint32_t *)((uint8_t *)ext->data + 1))
#define setProbeNum(ext, num) (*(uint32_t *)((uint8_t *)ext->data + 1) = htonl(num))
#define getHeaderLen(ext) ((ext->headerLen + 1) * SCION_EXT_LINE)
#define isProbeAck(ext) (*(uint8_t *)((ext)->data))

#endif
