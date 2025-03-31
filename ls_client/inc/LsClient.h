/*******************************************************************************
 *
 *  Copyright 2018, 2025 NXP
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#include "IChannel.h"

#ifdef __cplusplus
#include <vector>
extern "C" {

#endif
#ifndef LSCLIENT_H_
#define LSCLIENT_H_

#define STATUS_SUCCESS 0x00
#define STATUS_OKAY 0x00
#define STATUS_FAILED 0x03
#define STATUS_FILE_NOT_FOUND 0x05

typedef uint8_t tLSC_STATUS;

/*******************************************************************************
**
** Function:        LsClient_Start
**
** Description:     Starts the Sems Update
**
** Returns:         SUCCESS if ok.
**
*******************************************************************************/
unsigned char LsClient_Start(const char* name, const char* dest, uint8_t* pdata,
                             uint16_t len, uint8_t* respSW);

/*******************************************************************************
**
** Function:        performLSDownload
**
** Description:     Performs SEMS script execution
**
** Returns:         SUCCESS if ok
**
*******************************************************************************/
tLSC_STATUS performLSDownload(IChannel_t* data, const char* script_path,
                              std::streampos start_offset);

/*******************************************************************************
**
** Function:        LsClient_SemsSelect
**
** Description:     Selects SEMS AID
**
** Returns:         SUCCESS if ok
**
*******************************************************************************/
tLSC_STATUS LsClient_SemsSelect(IChannel_t* data);

/*******************************************************************************
**
** Function:        LsClient_SemsSendGetDataCmd
**
** Description:     Send plain cmd to Sems
**
** Returns:         Response from Sems for sent cmd
**
*******************************************************************************/
tLSC_STATUS LsClient_SemsSendGetDataCmd(uint8_t INS, uint8_t p2,
                                        std::vector<uint8_t>& response);

/*******************************************************************************
**
** Function:        LsClient_SemsDeSelect
**
** Description:     De-selects SEMS AID
**
** Returns:         SUCCESS if ok
**
*******************************************************************************/
tLSC_STATUS LsClient_SemsDeSelect();

void* phLS_memset(void* buff, int val, size_t len);
void* phLS_memcpy(void* dest, const void* src, size_t len);
void* phLS_memalloc(uint32_t size);
void  phLS_free(void* ptr);
void* phLS_calloc(size_t datatype, size_t size);

#endif /* LSCLIENT_H_ */

#ifdef __cplusplus
}

#endif
