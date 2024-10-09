/*
 * Copyright 2015-2019, 2025 NXP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ICHANNEL_H_
#define ICHANNEL_H_

#include <stdbool.h>
#include <stdint.h>
#ifdef NXP_BOOTTIME_UPDATE
#include "data_types.h"
typedef enum InterfaceInfo {
  INTF_NFC = 0,
  INTF_SE = 1,
} IntfInfo;
#endif
typedef struct IChannel {
  /*******************************************************************************
  **
  ** Function:        Open
  **
  ** Description:     Initialize the channel.
  **
  ** Returns:         True if ok.
  **
  *******************************************************************************/
  int16_t (*open)();
  /*******************************************************************************
  **
  ** Function:        close
  **
  ** Description:     Close the channel.
  **
  ** Returns:         True if ok.
  **
  *******************************************************************************/
  bool (*close)(int16_t mHandle);

  /*******************************************************************************
  **
  ** Function:        transceive
  **
  ** Description:     Send data to the secure element; read it's response.
  **                  xmitBuffer: Data to transmit.
  **                  xmitBufferSize: Length of data.
  **                  recvBuffer: Buffer to receive response.
  **                  recvBufferMaxSize: Maximum size of buffer.
  **                  recvBufferActualSize: Actual length of response.
  **                  timeoutMillisec: timeout in millisecond
  **
  ** Returns:         True if ok.
  **
  *******************************************************************************/
  bool (*transceive)(uint8_t* xmitBuffer, int32_t xmitBufferSize,
                     uint8_t* recvBuffer, int32_t recvBufferMaxSize,
                     int32_t& recvBufferActualSize, int32_t timeoutMillisec);

  /*******************************************************************************
  **
  ** Function:        transceiveRaw
  **
  ** Description:     Send data to the secure element; read it's response.
  **                  xmitBuffer: Data to transmit.
  **                  xmitBufferSize: Length of data.
  **                  recvBuffer: Buffer to receive response.
  **                  recvBufferMaxSize: Maximum size of buffer.
  **                  recvBufferActualSize: Actual length of response.
  **                  timeoutMillisec: timeout in millisecond
  **
  ** Returns:         True if ok.
  **
  *******************************************************************************/
  bool (*transceiveRaw)(uint8_t* xmitBuffer, int32_t xmitBufferSize,
                        uint8_t* recvBuffer, int32_t recvBufferMaxSize,
                        int32_t& recvBufferActualSize, int32_t timeoutMillisec);

  /*******************************************************************************
  **
  ** Function:        doeSE_Reset
  **
  ** Description:     Power OFF and ON to eSE
  **
  ** Returns:         None.
  **
  *******************************************************************************/

  void (*doeSE_Reset)();
#ifdef NXP_BOOTTIME_UPDATE
  /*******************************************************************************
  **
  ** Function:        doeSE_JcopDownLoadReset
  **
  ** Description:     Power OFF and ON to eSE during JCOP Update
  **
  ** Returns:         None.
  **
  *******************************************************************************/

  void (*doeSE_JcopDownLoadReset)();
  /*******************************************************************************
  **
  ** Variable:        tNfc_featureList
  **
  ** Description:     NFCC and eSE feature flags
  **
  ** Returns:         None.
  **
  *******************************************************************************/
  uint8_t (*getInterfaceInfo)();
#endif
  /******************************************************************************
  **
  ** Function:        parse_response
  **
  ** Description:     parses response received from SEMS agent
  **
  ** Returns:         true on success, false otherwise
  **
  *********************************************************************************/
  bool (*parse_response)(uint8_t* recvBuffer, int32_t recvBufferSize);
} IChannel_t;

#endif /* ICHANNEL_H_ */
