/******************************************************************************
 *
 *  Copyright 2018-2019, 2025 NXP
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

#include "LsLib.h"
#include "LsClient.h"
#include <cutils/log.h>
#include <dirent.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

#undef LOG_TAG
#define LOG_TAG "LsLib"

#define GENERATED_HASH_SIZE 20

uint8_t datahex(char c);
void updateLsAid(uint8_t intfInfo);
/*******************************************************************************
**
** Function:        LsClient_Start
**
** Description:     Starts the Sems update
**
** Returns:         SUCCESS if ok.
**
*******************************************************************************/
tLSC_STATUS LsClient_Start(const char* name, const char* dest,
                           std::streampos start_offset, uint8_t* pdata,
                           uint16_t len, uint8_t* respSW) {
  static const char fn[] = "LsClient_Start";
  tLSC_STATUS status = STATUS_FAILED;
  if (name != NULL) {
    ALOGE("%s: name is %s", fn, name);
    ALOGE("%s: Dest is %s", fn, dest);
    status = Perform_LSC(name, dest, start_offset, pdata, len, respSW);
  } else {
    ALOGE("Invalid parameter");
  }
  ALOGE("%s: Exit; status=0x0%X", fn, status);
  return status;
}

tLSC_STATUS LsClient_SemsSelect(IChannel_t* data) {
  tLSC_STATUS status = STATUS_FAILED;
  if (!initialize((IChannel_t*)data)) {
    ALOGE("%s: initialize failed", __FUNCTION__);
  } else {
    status = LsLib_SelectSemsAID();
  }
  return status;
}

tLSC_STATUS LsClient_SemsSendGetDataCmd(uint8_t INS, uint8_t p2,
                                        std::vector<uint8_t>& response) {
  return LsLib_SendCmd(INS, p2, response);
}

tLSC_STATUS LsClient_SemsDeSelect() { return LsLib_SemsDeSelect(); }

/*******************************************************************************
**
** Function:        performLSDownload
**
** Description:     Perform LS during hal init
**
** Returns:         SUCCESS of ok
**
*******************************************************************************/
tLSC_STATUS performLSDownload(IChannel_t* data, const char* script_path,
                              std::streampos start_offset) {
  tLSC_STATUS status = STATUS_FAILED;
#ifdef NXP_BOOTTIME_UPDATE
  const char* lsUpdateBackupPath =
      "/vendor/etc/loaderservice_updater.txt";
  const char* lsUpdateBackupOutPath[2] =
  {"/data/vendor/nfc/loaderservice_updater_out.txt",
   "/data/vendor/secure_element/loaderservice_updater_out.txt",};
#endif
  IChannel_t* mchannel = (IChannel_t*)data;

  /*generated SHA-1 string for secureElementLS
  This will remain constant as handled in secureElement HAL*/
  const char sha1[] = "6d583e84f2710e6b0f06beebc1a12a1083591373";
  uint8_t hash[GENERATED_HASH_SIZE] = {};

  for (int i = 0; i < (2 * GENERATED_HASH_SIZE); i = i + 2) {
    hash[i / 2] =
        (((datahex(sha1[i]) & 0x0F) << 4) | (datahex(sha1[i + 1]) & 0x0F));
  }

#ifdef NXP_BOOTTIME_UPDATE
  /*Check and update if any new LS AID is available*/
  updateLsAid(mchannel->getInterfaceInfo());

  if(!initialize ((IChannel_t*) data))
    return status;


  uint8_t resSW[4] = {0x4e, 0x02, 0x69, 0x87};
  FILE* fIn, *fOut;
  if ((fIn = fopen(lsUpdateBackupPath, "rb")) == NULL) {
    ALOGE("%s Cannot open file %s\n", __func__, lsUpdateBackupPath);
    ALOGE("%s Error : %s", __func__, strerror(errno));
    return status;
  } else {
    ALOGD("%s File opened %s\n", __func__, lsUpdateBackupPath);
    if ((fOut = fopen(lsUpdateBackupOutPath[mchannel->getInterfaceInfo()], "wb")) == NULL) {
      ALOGE("%s Failed to open file %s\n", __func__,
        lsUpdateBackupOutPath[mchannel->getInterfaceInfo()]);
      fclose(fIn);
      return status;
    } else {
      ALOGD("%s File opened %s\n", __func__,
        lsUpdateBackupOutPath[mchannel->getInterfaceInfo()]);
      fclose(fIn);
      fclose(fOut);
    }
    status = LsClient_Start(lsUpdateBackupPath,
                            lsUpdateBackupOutPath[mchannel->getInterfaceInfo()],
                            0, (uint8_t*)hash, (uint16_t)sizeof(hash), resSW);
    resSW[0]=0x4e;
    ALOGD("%s LSC_Start completed\n", __func__);
    if (status == STATUS_SUCCESS) {
      if (remove(lsUpdateBackupPath) == 0) {
        ALOGD("%s  : %s file deleted successfully\n", __func__,
              lsUpdateBackupPath);
      } else {
        ALOGD("%s  : %s file deletion failed!!!\n", __func__,
              lsUpdateBackupPath);
      }
    }
  }
#else

  if (initialize((IChannel_t*)data)) {
    uint8_t resSW[4] = {0x4e, 0x02, 0x69, 0x87};
    FILE* fIn;
    if ((fIn = fopen(script_path, "rb")) == NULL) {
      ALOGE("%s Cannot open file %s: error- %s\n", __func__, script_path,
            strerror(errno));
    } else {
      fclose(fIn);
      status = LsClient_Start(script_path, NULL, start_offset, (uint8_t*)hash,
                              (uint16_t)sizeof(hash), resSW);
      resSW[0] = 0x4e;
      if (status == STATUS_SUCCESS) {
        ALOGD("%s LsClient_Start completed\n", __func__);
      }
    }
  }
  finalize();
#endif
  ALOGD("%s pthread_exit\n", __func__);
  return status;
}

/*******************************************************************************
**
** Function:        datahex
**
** Description:     Converts char to uint8_t
**
** Returns:         uint8_t variable
**
*******************************************************************************/
uint8_t datahex(char c) {
  uint8_t value = 0;
  if (c >= '0' && c <= '9')
    value = (c - '0');
  else if (c >= 'A' && c <= 'F')
    value = (10 + (c - 'A'));
  else if (c >= 'a' && c <= 'f')
    value = (10 + (c - 'a'));
  return value;
}

#ifdef NXP_BOOTTIME_UPDATE
/*******************************************************************************
**
** Function:        updateLsAid
**
** Description:     Store AID in LS_SELF_UPDATE_AID_IDX of ArrayOfAIDs if new LS
**                  AID is available after LS Self Update
**
** Returns:         None
**
*******************************************************************************/
void updateLsAid(uint8_t intfInfo) {
  ALOGD_IF( "%s Enter\n", __func__);

  FILE* fAID_MEM = NULL;
  fAID_MEM = fopen(AID_MEM_PATH[intfInfo], "r");

  if (fAID_MEM == NULL) {
    ALOGE("%s: AID data file does not exists", __func__);
    return;
  }

  uint8_t aidLen = 0x00;
  int32_t wStatus = 0;

  while (!(feof(fAID_MEM))) {
    wStatus = FSCANF_BYTE(fAID_MEM, "%2x",
                          &ArrayOfAIDs[LS_SELF_UPDATE_AID_IDX][aidLen++]);
    if (wStatus == 0) {
      ALOGE("%s: exit: Error during read AID data", __func__);
      ArrayOfAIDs[LS_SELF_UPDATE_AID_IDX][0] = 0x00;
      break;
    }
  }
  if ((wStatus > 0x00) && (aidLen > 0x00)) {
    ArrayOfAIDs[LS_SELF_UPDATE_AID_IDX][0] = aidLen - 1;
  }
  fclose(fAID_MEM);
}
#endif
void* phLS_memset(void* buff, int val, size_t len) {
  return memset(buff, val, len);
}

void* phLS_memcpy(void* dest, const void* src, size_t len) {
  return memcpy(dest, src, len);
}

void* phLS_memalloc(uint32_t size) { return malloc(size); }

void phLS_free(void* ptr) { return free(ptr); }

void* phLS_calloc(size_t datatype, size_t size) {
  return calloc(datatype, size);
}
