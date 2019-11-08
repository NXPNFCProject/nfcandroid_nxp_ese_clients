/*
 * Copyright (C) 2015-2019 NXP Semiconductors
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

#include "data_types.h"
#include "IChannel.h"
#include <stdio.h>

typedef struct JcopOs_TranscieveInfo
{
    int32_t timeout;
    uint8_t sRecvData[1024];
    uint8_t *sSendData;
    int32_t sSendlength;
    int sRecvlength;
}JcopOs_TranscieveInfo_t;

typedef struct JcopOs_Version_Info
{
    uint8_t osid;
    uint8_t ver1;
    uint8_t ver0;
    uint8_t OtherValid;
    uint8_t ver_status;
}JcopOs_Version_Info_t;

typedef struct JcopOs_Uai_QueryInfo {
  uint16_t CSNData;
  uint16_t RSNData;
  uint16_t FSNData;
  uint16_t OSIDData;
} JcopOs_Uai_QueryInfo;

typedef struct JcopOs_ImageInfo
{
    FILE *fp;
    int   fls_size;
    char  fls_path[256];
    int   index;
    uint8_t cur_state;
    JcopOs_Version_Info_t    version_info;
    JcopOs_Uai_QueryInfo uai_info;
}JcopOs_ImageInfo_t;
typedef struct JcopOs_Dwnld_Context
{
    JcopOs_Version_Info_t    version_info;
    JcopOs_ImageInfo_t       Image_info;
    JcopOs_TranscieveInfo_t  pJcopOs_TransInfo;
    IChannel_t               *channel;
}JcopOs_Dwnld_Context_t,*pJcopOs_Dwnld_Context_t;

typedef enum {
  OSID_0 = 0,
  OSID_1 = 1,
  OSID_2 = 2,
  OSID_SU1 = 0x11,
  OSID_JCOP = 0x5A,
} JcopOs_OSID_state;

typedef enum {
  OSU_UAI_TRIGGER_STATE = 0,
  OSU_UAI_CMDS_STATE = 1,
  OSU_TRIGGER_STATE = 2,
  OSU_GETINFO_STATE1 = 3,
  OSU_LOAD_APDU_STATE1 = 4,
  OSU_GETINFO_STATE2 = 5,
  OSU_LOAD_APDU_STATE2 = 6,
  OSU_GETINFO_STATE3 = 7,
  OSU_LOAD_APDU_STATE3 = 8,
} JcopOs_OSU_Sequence_state;

typedef enum {
  UAI_STATE_DEFAULT = 0,
  UAI_STATE_CCI_VALID = 0x1111,
  UAI_STATE_JCI_VALID = 0x2222,
  UAI_STATE_IDLE = 0x5A5A,
  UAI_STATE_ERROR = 0xA5A5,
} JcopOs_UAI_state;

static uint8_t Trigger_APDU[] = {0x4F, 0x70, 0x80, 0x13, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00};
static uint8_t GetInfo_APDU[] = {0x00, //CLA
                               0xA4, 0x04, 0x00, 0x0C, //INS, P1, P2, Lc
                               0xD2, 0x76, 0x00, 0x00, 0x85, 0x41, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,   //Data
                               0x00 //Le
                              };
static uint8_t GetInfo_Data[] = {0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x72, 0x4F, 0x53};

static uint8_t Uai_Trigger_APDU[] = {0x4F, 0x70, 0x80, 0x13, 0x04, 0x4A, 0x55, 0x41, 0x49, 0x00};
static uint8_t Uai_GetInfo_APDU[] = {0x80,0xCA,0x00,0xFE,0x02,0xDF,0x43,0x00};

#define OSID_OFFSET  9
#define VER1_OFFSET  10
#define VER0_OFFSET  11
#define JCOPOS_HEADER_LEN 5

#define JCOP_UPDATE_STATE0 0
#define JCOP_UPDATE_STATE1 1
#define JCOP_UPDATE_STATE2 2
#define JCOP_UPDATE_STATE3 3
#define JCOP_UPDATE_STATE_TRIGGER_APDU 4

#define JCOP_MAX_RETRY_CNT 3
//#define JCOP_INFO_PATH     "/data/vendor/nfc/jcop_info.txt"

#define JCOP_MAX_BUF_SIZE 10240

#define JCOP_UAI_INFO_INDEX 7

#define JCOP_UAI_CSN_OFFSET 5
#define JCOP_UAI_CSN_INDEX (JCOP_UAI_INFO_INDEX + JCOP_UAI_CSN_OFFSET)

#define JCOP_UAI_RSN_OFFSET 9
#define JCOP_UAI_RSN_INDEX (JCOP_UAI_INFO_INDEX + JCOP_UAI_RSN_OFFSET)

#define JCOP_UAI_FSN_OFFSET 13
#define JCOP_UAI_FSN_INDEX (JCOP_UAI_INFO_INDEX + JCOP_UAI_FSN_OFFSET)

#define JCOP_UAI_OSID_OFFSET 21
#define JCOP_UAI_OSID_INDEX (JCOP_UAI_INFO_INDEX + JCOP_UAI_OSID_OFFSET)

class JcopOsDwnld
{
public:

/*******************************************************************************
**
** Function:        getInstance
**
** Description:     Get the SecureElement singleton object.
**
** Returns:         SecureElement object.
**
*******************************************************************************/
static JcopOsDwnld* getInstance ();


/*******************************************************************************
**
** Function:        getJcopOsFileInfo
**
** Description:     Verify all the updater files required for download
**                  are present or not
**
** Returns:         True if ok.
**
*******************************************************************************/
bool getJcopOsFileInfo();

/*******************************************************************************
**
** Function:        initialize
**
** Description:     Initialize all member variables.
**                  native: Native data.
**
** Returns:         True if ok.
**
*******************************************************************************/
bool initialize (IChannel_t *channel);

/*******************************************************************************
**
** Function:        finalize
**
** Description:     Release all resources.
**
** Returns:         None
**
*******************************************************************************/
void finalize ();

tJBL_STATUS JcopOs_Download();

tJBL_STATUS TriggerApdu(JcopOs_ImageInfo_t* pVersionInfo, tJBL_STATUS status, JcopOs_TranscieveInfo_t* pTranscv_Info);

tJBL_STATUS UaiTriggerApdu(JcopOs_ImageInfo_t* pVersionInfo, tJBL_STATUS status, JcopOs_TranscieveInfo_t* pTranscv_Info);

tJBL_STATUS GetInfo(JcopOs_ImageInfo_t* pVersionInfo, tJBL_STATUS status, JcopOs_TranscieveInfo_t* pTranscv_Info);

tJBL_STATUS load_JcopOS_image(JcopOs_ImageInfo_t *Os_info, tJBL_STATUS status, JcopOs_TranscieveInfo_t *pTranscv_Info);

tJBL_STATUS JcopOs_update_seq_handler();

tJBL_STATUS SendUAICmds(JcopOs_ImageInfo_t *Os_info, tJBL_STATUS status, JcopOs_TranscieveInfo_t *pTranscv_Info);

tJBL_STATUS DeriveJcopOsu_State(JcopOs_ImageInfo_t *Os_info,
                                uint8_t *dh_osu_state);

IChannel_t *mchannel;

private:
static JcopOsDwnld sJcopDwnld;
bool mIsInit;
tJBL_STATUS GetJcopOsState(JcopOs_ImageInfo_t *Os_info, uint8_t *counter,
                           JcopOs_TranscieveInfo_t *pTranscv_Info);
tJBL_STATUS SetJcopOsState(JcopOs_ImageInfo_t *Os_info, uint8_t state);
tJBL_STATUS Get_UAI_JcopOsState(JcopOs_ImageInfo_t *pVersionInfo,
                                uint8_t *dh_osu_state,
                                JcopOs_TranscieveInfo_t *pTranscv_Info);
void SetUAI_Data(JcopOs_ImageInfo_t *pVersionInfo, uint8_t *pData);
};
