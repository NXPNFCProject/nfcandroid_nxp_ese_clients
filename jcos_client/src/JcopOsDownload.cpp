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
#include <IChannel.h>
#include <JcopOsDownload.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <errno.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

 using android::base::StringPrintf;

 JcopOsDwnld JcopOsDwnld::sJcopDwnld;
 static int32_t gTransceiveTimeout = 120000;
 uint8_t isUaiEnabled = false;
 uint8_t isPatchUpdate = false;

 tJBL_STATUS (JcopOsDwnld::* JcopOs_dwnld_seqhandler[])(
     JcopOs_ImageInfo_t* pContext, tJBL_STATUS status,
     JcopOs_TranscieveInfo_t* pInfo) = {
     &JcopOsDwnld::UaiTriggerApdu,    &JcopOsDwnld::SendUAICmds,
     &JcopOsDwnld::TriggerApdu,       &JcopOsDwnld::GetInfo,
     &JcopOsDwnld::load_JcopOS_image, &JcopOsDwnld::GetInfo,
     &JcopOsDwnld::load_JcopOS_image, &JcopOsDwnld::GetInfo,
     &JcopOsDwnld::load_JcopOS_image, NULL};

 pJcopOs_Dwnld_Context_t gpJcopOs_Dwnld_Context = NULL;
 static const char* path[3] = {"/vendor/etc/JcopOs_Update1.apdu",
                               "/vendor/etc/JcopOs_Update2.apdu",
                               "/vendor/etc/JcopOs_Update3.apdu"};
 static const char* JCOP_INFO_PATH[2] = {
     "/data/vendor/nfc/jcop_info.txt",
     "/data/vendor/secure_element/jcop_info.txt"};

 static const char* uai_path[2] = {"/vendor/etc/cci.apdu",
                                   "/vendor/etc/jci.apdu"};

 inline int FSCANF_BYTE(FILE* stream, const char* format, void* pVal) {
   int Result = 0;

   if ((NULL != stream) && (NULL != format) && (NULL != pVal)) {
     unsigned int dwVal;
     unsigned char* pTmp = (unsigned char*)pVal;
     Result = fscanf(stream, format, &dwVal);

     (*pTmp) = (unsigned char)(dwVal & 0x000000FF);
   }
   return Result;
}

/*******************************************************************************
**
** Function:        getInstance
**
** Description:     Get the JcopOsDwnld singleton object.
**
** Returns:         JcopOsDwnld object.
**
*******************************************************************************/
JcopOsDwnld* JcopOsDwnld::getInstance()
{
    JcopOsDwnld *jd = new JcopOsDwnld();
    return jd;
}

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
bool JcopOsDwnld::getJcopOsFileInfo()
{
    static const char fn [] = "JcopOsDwnld::getJcopOsFileInfo";
    bool status = true;
    struct stat st;
    isPatchUpdate = false;
    int isFilepresent = 0;
    LOG(INFO) << StringPrintf("%s: Enter", fn);
    // LOG(INFO)
    //<< StringPrintf("%s: Enter", fn);
    for (int num = 0; num < 2; num++)
    {
        if (stat(uai_path[num], &st))
        {
            status = false;
        }
    }
    /*If UAI specific files are present*/
    if(status == true)
    {
        isUaiEnabled = true;
        for (int num = 0; num < 3; num++)
        {
           if (stat(path[num], &st))
              status = false;
           else
              isFilepresent++;
        }
        if(isFilepresent == 1 && status == false && !(stat(path[0], &st)))
        {
           isPatchUpdate = true;
           status = true;
        } else if(isFilepresent == 2 && status == false) {
           isPatchUpdate = false;
           status = false;
        }
    }
    LOG(INFO) << StringPrintf("%s: Exit Status %d", fn, status);
    return status;
}

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
bool JcopOsDwnld::initialize (IChannel_t *channel)
{
    static const char fn [] = "JcopOsDwnld::initialize";
    isUaiEnabled = false;
    LOG(INFO) << StringPrintf("%s: enter", fn);

    if (!getJcopOsFileInfo())
    {
      LOG(INFO) << StringPrintf("%s: insufficient resources, file not present",
                                fn);
      return (false);
    }
    gpJcopOs_Dwnld_Context = (pJcopOs_Dwnld_Context_t)malloc(sizeof(JcopOs_Dwnld_Context_t));
    if(gpJcopOs_Dwnld_Context != NULL)
    {
        memset((void *)gpJcopOs_Dwnld_Context, 0, (uint32_t)sizeof(JcopOs_Dwnld_Context_t));
        gpJcopOs_Dwnld_Context->channel = (IChannel_t*)malloc(sizeof(IChannel_t));
        if(gpJcopOs_Dwnld_Context->channel != NULL)
        {
            memset(gpJcopOs_Dwnld_Context->channel, 0, sizeof(IChannel_t));
        }
        else
        {
          LOG(INFO) << StringPrintf(
              "%s: Memory allocation for IChannel is failed", fn);
          return (false);
        }
        gpJcopOs_Dwnld_Context->pJcopOs_TransInfo.sSendData = (uint8_t*)malloc(sizeof(uint8_t)*JCOP_MAX_BUF_SIZE);
        if(gpJcopOs_Dwnld_Context->pJcopOs_TransInfo.sSendData != NULL)
        {
            memset(gpJcopOs_Dwnld_Context->pJcopOs_TransInfo.sSendData, 0, JCOP_MAX_BUF_SIZE);
        }
        else
        {
          LOG(INFO) << StringPrintf(
              "%s: Memory allocation for SendBuf is failed", fn);
          return (false);
        }
    }
    else
    {
      LOG(INFO) << StringPrintf("%s: Memory allocation failed", fn);
      return (false);
    }
    mIsInit = true;
    memcpy(gpJcopOs_Dwnld_Context->channel, channel, sizeof(IChannel_t));
    LOG(INFO) << StringPrintf("%s: exit", fn);
    return (true);
}
/*******************************************************************************
**
** Function:        finalize
**
** Description:     Release all resources.
**
** Returns:         None
**
*******************************************************************************/
void JcopOsDwnld::finalize ()
{
    static const char fn [] = "JcopOsDwnld::finalize";
    LOG(INFO) << StringPrintf("%s: enter", fn);
    mIsInit       = false;
    if(gpJcopOs_Dwnld_Context != NULL)
    {
        if(gpJcopOs_Dwnld_Context->channel != NULL)
        {
            free(gpJcopOs_Dwnld_Context->channel);
            gpJcopOs_Dwnld_Context->channel = NULL;
        }
        if(gpJcopOs_Dwnld_Context->pJcopOs_TransInfo.sSendData != NULL)
        {
            free(gpJcopOs_Dwnld_Context->pJcopOs_TransInfo.sSendData);
            gpJcopOs_Dwnld_Context->pJcopOs_TransInfo.sSendData = NULL;
        }
        free(gpJcopOs_Dwnld_Context);
        gpJcopOs_Dwnld_Context = NULL;
    }
    LOG(INFO) << StringPrintf("%s: exit", fn);
}

/*******************************************************************************
**
** Function:        JcopOs_Download
**
** Description:     Starts the OS download sequence
**
** Returns:         Success if ok.
**
*******************************************************************************/
tJBL_STATUS JcopOsDwnld::JcopOs_Download()
{
    static const char fn [] = "JcopOsDwnld::JcopOs_Download";
    tJBL_STATUS wstatus = STATUS_FAILED;
    uint8_t retry_cnt = 0x00;
    LOG(INFO) << StringPrintf("%s: Enter:", fn);
    if(mIsInit == false)
    {
      LOG(INFO) << StringPrintf("%s: JcopOs Dwnld is not initialized", fn);
      wstatus = STATUS_FAILED;
    }
    else
    {
        do
        {
            wstatus = JcopOsDwnld::JcopOs_update_seq_handler();
            if(wstatus == STATUS_FAILED)
                retry_cnt++;
            else
                break;
        }while(retry_cnt < JCOP_MAX_RETRY_CNT);
    }
    LOG(INFO) << StringPrintf("%s: Exit; status = 0x%x", fn, wstatus);
    return wstatus;
}
/*******************************************************************************
**
** Function:        JcopOs_update_seq_handler
**
** Description:     Performs the JcopOS download sequence
**
** Returns:         Success if ok.
**
*******************************************************************************/
tJBL_STATUS JcopOsDwnld::JcopOs_update_seq_handler()
{
    static const char fn[] = "JcopOsDwnld::JcopOs_update_seq_handler";
    uint8_t seq_counter = 0;
    JcopOs_ImageInfo_t update_info = (JcopOs_ImageInfo_t )gpJcopOs_Dwnld_Context->Image_info;
    JcopOs_TranscieveInfo_t trans_info = (JcopOs_TranscieveInfo_t )gpJcopOs_Dwnld_Context->pJcopOs_TransInfo;
    update_info.index = 0x00;
    update_info.cur_state = 0x00;
    tJBL_STATUS status = STATUS_FAILED;

    LOG(INFO) << StringPrintf("%s: enter", fn);
    status = GetJcopOsState(&update_info, &seq_counter, &trans_info);
    if(status != STATUS_SUCCESS)
    {
        LOG(ERROR) << StringPrintf("Error in getting JcopOsState info");
    }
    else
    {
      LOG(ERROR) << StringPrintf("seq_counter %d", seq_counter);
      while ((JcopOs_dwnld_seqhandler[seq_counter]) != NULL) {
        status = STATUS_FAILED;
        status = (*this.*(JcopOs_dwnld_seqhandler[seq_counter]))(
            &update_info, status, &trans_info);
        if (STATUS_SUCCESS != status) {
          LOG(ERROR) << StringPrintf("%s: exiting; status=0x0%X", fn, status);
          break;
        }
        seq_counter++;
        }
        if(status == STATUS_SUCCESS)
        {
          int32_t recvBufferActualSize = 0;
          uint8_t select[] = {0, 0xA4, 0x04, 0, 0};
          uint16_t handle = gpJcopOs_Dwnld_Context->channel->open();
          usleep(100*1000);
          LOG(ERROR) << StringPrintf("%s: Issue First APDU", fn);
          gpJcopOs_Dwnld_Context->channel->transceive(select, sizeof(select),
          trans_info.sRecvData, 1024, recvBufferActualSize, trans_info.timeout);

          gpJcopOs_Dwnld_Context->channel->close(handle);
        }
    }
    return status;
}

/*******************************************************************************
**
** Function:        TriggerApdu
**
** Description:     Switch to updater OS
**
** Returns:         Success if ok.
**
*******************************************************************************/
tJBL_STATUS JcopOsDwnld::TriggerApdu(JcopOs_ImageInfo_t* pVersionInfo, tJBL_STATUS status, JcopOs_TranscieveInfo_t* pTranscv_Info)
{
    static const char fn [] = "JcopOsDwnld::TriggerApdu";
    bool stat = false;
    IChannel_t *mchannel = gpJcopOs_Dwnld_Context->channel;
    int32_t recvBufferActualSize = 0;

    LOG(INFO) << StringPrintf("%s: enter;", fn);
    if(pTranscv_Info == NULL ||
       pVersionInfo == NULL)
    {
      LOG(INFO) << StringPrintf("%s: Invalid parameter", fn);
      status = STATUS_FAILED;
    }
    else
    {
        pTranscv_Info->timeout = gTransceiveTimeout;
        pTranscv_Info->sSendlength = (int32_t)sizeof(Trigger_APDU);
        pTranscv_Info->sRecvlength = 1024;//(int32_t)sizeof(int32_t);
        memcpy(pTranscv_Info->sSendData, Trigger_APDU, pTranscv_Info->sSendlength);

        LOG(INFO) << StringPrintf("%s: Calling Secure Element Transceive", fn);
        stat = mchannel->transceiveRaw (pTranscv_Info->sSendData,
                                pTranscv_Info->sSendlength,
                                pTranscv_Info->sRecvData,
                                pTranscv_Info->sRecvlength,
                                recvBufferActualSize,
                                pTranscv_Info->timeout);
        if (stat != true)
        {
            status = STATUS_FAILED;
            LOG(ERROR) << StringPrintf("%s: SE transceive failed status = 0x%X", fn, status);//Stop JcopOs Update
        }
        else if(((pTranscv_Info->sRecvData[recvBufferActualSize-2] == 0x68) &&
               (pTranscv_Info->sRecvData[recvBufferActualSize-1] == 0x81))||
               ((pTranscv_Info->sRecvData[recvBufferActualSize-2] == 0x90) &&
               (pTranscv_Info->sRecvData[recvBufferActualSize-1] == 0x00))||
               ((pTranscv_Info->sRecvData[recvBufferActualSize-2] == 0x6F) &&
               (pTranscv_Info->sRecvData[recvBufferActualSize-1] == 0x00)))
        {
            mchannel->doeSE_JcopDownLoadReset();
            status = STATUS_OKAY;
            LOG(INFO) << StringPrintf(
                "%s: Trigger APDU Transceive status = 0x%X", fn, status);
        }
        else
        {
            /* status {90, 00} */
            status = STATUS_OKAY;
        }
    }
    LOG(INFO) << StringPrintf("%s: exit; status = 0x%X", fn, status);
    return status;
}

/*******************************************************************************
**
** Function:        SendUAICmds
**
** Description:     Perform UAI Authentication
**
** Returns:         Success if ok.
**
*******************************************************************************/
tJBL_STATUS JcopOsDwnld::SendUAICmds(JcopOs_ImageInfo_t* Os_info, tJBL_STATUS status, JcopOs_TranscieveInfo_t* pTranscv_Info)
{
    static const char fn [] = "JcopOsDwnld::SendUAICmds";
    bool stat = false;
    int wResult;
    int32_t wIndex,wCount=0;
    int32_t wLen;
    IChannel_t *mchannel = gpJcopOs_Dwnld_Context->channel;
    int32_t recvBufferActualSize = 0;
    int i = 0;

    LOG(INFO) << StringPrintf("%s: enter;", fn);

    if(!pTranscv_Info || !Os_info) {
      LOG(INFO) << StringPrintf("%s: Invalid parameter", fn);
      return STATUS_FAILED;
    }
    if(!isUaiEnabled) {
        goto exit;
    }
    for(i = 0; i < 2; i++)
    {
        Os_info->fp = fopen(uai_path[i], "r");
        if (Os_info->fp == NULL) {
            LOG(ERROR) << StringPrintf("Error opening CCI file <%s> for reading: %s",
                        Os_info->fls_path, strerror(errno));
            return STATUS_FILE_NOT_FOUND;
        }
        wResult = fseek(Os_info->fp, 0L, SEEK_END);
        if (wResult) {
            LOG(ERROR) << StringPrintf("Error seeking end CCI file %s", strerror(errno));
            goto exit;
        }
        Os_info->fls_size = ftell(Os_info->fp);
        if (Os_info->fls_size < 0) {
            LOG(ERROR) << StringPrintf("Error ftelling file %s", strerror(errno));
            goto exit;
        }
        wResult = fseek(Os_info->fp, 0L, SEEK_SET);
        if (wResult) {
            LOG(ERROR) << StringPrintf("Error seeking start image file %s", strerror(errno));
            goto exit;
        }
        while(!feof(Os_info->fp))
        {
            wIndex=0;
            wLen=0;
            wCount=0;
            memset(pTranscv_Info->sSendData,0x00,JCOP_MAX_BUF_SIZE);
            pTranscv_Info->sSendlength=0;

            LOG(ERROR) << StringPrintf("%s; wIndex = 0", fn);
            for(wCount =0; (wCount < 5 && !feof(Os_info->fp)); wCount++, wIndex++)
            {
                wResult = FSCANF_BYTE(Os_info->fp,"%2X",&pTranscv_Info->sSendData[wIndex]);
                if(wResult == 0) {
                    LOG(ERROR) << StringPrintf("%s: Failed in fscanf", fn);
                }
            }
            if(wResult != 0)
            {
                wLen = pTranscv_Info->sSendData[4];
                LOG(ERROR) << StringPrintf("%s; Read 5byes success & len=%d", fn,wLen);
                if(wLen == 0x00)
                {
                    LOG(ERROR) << StringPrintf("%s: Extended APDU", fn);
                    wResult = FSCANF_BYTE(Os_info->fp,"%2X",&pTranscv_Info->sSendData[wIndex++]);
                    if(wResult == 0) {
                        LOG(ERROR) << StringPrintf("%s: Failed in fscanf", fn);
                    }
                    wResult = FSCANF_BYTE(Os_info->fp,"%2X",&pTranscv_Info->sSendData[wIndex++]);
                    if(wResult == 0) {
                        LOG(ERROR) << StringPrintf("%s: Failed in fscanf", fn);
                    }
                    wLen = ((pTranscv_Info->sSendData[5] << 8) | (pTranscv_Info->sSendData[6]));
                }
                for(wCount =0; (wCount < wLen && !feof(Os_info->fp)); wCount++, wIndex++)
                {
                    wResult = FSCANF_BYTE(Os_info->fp,"%2X",&pTranscv_Info->sSendData[wIndex]);
                    if(wResult == 0) {
                        LOG(ERROR) << StringPrintf("%s: Failed in fscanf", fn);
                    }
                }
            }
            else
            {
                LOG(ERROR) << StringPrintf("%s: JcopOs image Read failed", fn);
                goto exit;
            }
            pTranscv_Info->sSendlength = wIndex;
            LOG(ERROR) << StringPrintf("%s: start transceive for length %d", fn, pTranscv_Info->sSendlength);
            if((pTranscv_Info->sSendlength != 0x03) &&
               (pTranscv_Info->sSendData[0] != 0x00) &&
               (pTranscv_Info->sSendData[1] != 0x00))
            {

                stat = mchannel->transceiveRaw(pTranscv_Info->sSendData,
                                        pTranscv_Info->sSendlength,
                                        pTranscv_Info->sRecvData,
                                        pTranscv_Info->sRecvlength,
                                        recvBufferActualSize,
                                        pTranscv_Info->timeout);
            }
            else
            {
                LOG(ERROR) << StringPrintf("%s: Invalid packet", fn);
                continue;
            }
            if(stat != true)
            {
                LOG(ERROR) << StringPrintf("%s: Transceive failed; status=0x%X", fn, stat);
                status = STATUS_FAILED;
                goto exit;
            }
            else if(recvBufferActualSize != 0 &&
                    pTranscv_Info->sRecvData[recvBufferActualSize-2] == 0x90 &&
                    pTranscv_Info->sRecvData[recvBufferActualSize-1] == 0x00)
            {
                status = STATUS_SUCCESS;
            }
            else if(pTranscv_Info->sRecvData[recvBufferActualSize-2] == 0x6F &&
                    pTranscv_Info->sRecvData[recvBufferActualSize-1] == 0x00)
            {
                LOG(ERROR) << StringPrintf("%s: JcopOs is already upto date-No update required exiting", fn);
                Os_info->version_info.ver_status = STATUS_UPTO_DATE;
                status = STATUS_FAILED;
                break;
            }
            else
            {
                status = STATUS_FAILED;
                LOG(ERROR) << StringPrintf("%s: pTranscv_Info->sRecvData[recvBufferActualSize-1] = 0x%x%x recvBufferActualSize = %d", fn,
                        pTranscv_Info->sRecvData[recvBufferActualSize-2], pTranscv_Info->sRecvData[recvBufferActualSize-1],recvBufferActualSize);
                LOG(ERROR) << StringPrintf("%s: Invalid response", fn);
                goto exit;
            }
        }
        fclose(Os_info->fp);
        Os_info->fp = NULL;
    }
exit:
    LOG(ERROR) << StringPrintf("%s close fp and exit; status= 0x%X", fn,status);

    if(status == STATUS_SUCCESS) {
        SetJcopOsState(Os_info, JCOP_UPDATE_STATE_TRIGGER_APDU);
    } else {
      /*Only required in case of secure_elemnt/SPI interface*/
      if(mchannel->doeSE_Reset != NULL) {
        mchannel->doeSE_Reset();
        usleep(100*1000);
      }
    }
    /* Reset to restart UAI
     * and MW context reset(SPI) & power recycle
     * in SMB*/
    mchannel->doeSE_JcopDownLoadReset();
    if(Os_info->fp) {
        fclose(Os_info->fp);
        Os_info->fp = NULL;
    }

    return status;
}
/*******************************************************************************
**
** Function:        UaiTriggerApdu
**
** Description:     Switch to updater OS
**
** Returns:         Success if ok.
**
*******************************************************************************/
tJBL_STATUS JcopOsDwnld::UaiTriggerApdu(JcopOs_ImageInfo_t* pVersionInfo, tJBL_STATUS status, JcopOs_TranscieveInfo_t* pTranscv_Info)
{
    static const char fn [] = "JcopOsDwnld::UaiTriggerApdu";
    bool stat = false;
    IChannel_t *mchannel = gpJcopOs_Dwnld_Context->channel;
    int32_t recvBufferActualSize = 0;

    LOG(INFO) << StringPrintf("%s: enter;", fn);

    if(!isUaiEnabled)
    {
        return true;
    }
    if(pTranscv_Info == NULL ||
       pVersionInfo == NULL)
    {
      LOG(INFO) << StringPrintf("%s: Invalid parameter", fn);
      status = STATUS_FAILED;
    }
    else
    {
        pTranscv_Info->timeout = gTransceiveTimeout;
        pTranscv_Info->sSendlength = (int32_t)sizeof(Uai_Trigger_APDU);
        pTranscv_Info->sRecvlength = 1024;//(int32_t)sizeof(int32_t);
        memcpy(pTranscv_Info->sSendData, Uai_Trigger_APDU, pTranscv_Info->sSendlength);

        LOG(INFO) << StringPrintf("%s: Calling Secure Element Transceive", fn);
        stat = mchannel->transceiveRaw (pTranscv_Info->sSendData,
                                pTranscv_Info->sSendlength,
                                pTranscv_Info->sRecvData,
                                pTranscv_Info->sRecvlength,
                                recvBufferActualSize,
                                pTranscv_Info->timeout);
        if (stat != true)
        {
            status = STATUS_FAILED;
            LOG(ERROR) << StringPrintf("%s: SE transceive failed status = 0x%X", fn, status);//Stop JcopOs Update
        }
        else if(((pTranscv_Info->sRecvData[recvBufferActualSize-2] == 0x90) &&
               (pTranscv_Info->sRecvData[recvBufferActualSize-1] == 0x00)))
        {
            /*mchannel->doeSE_JcopDownLoadReset();*/
            status = STATUS_OKAY;
            LOG(INFO) << StringPrintf(
                "%s: Trigger APDU Transceive status = 0x%X", fn, status);
        }
        else
        {
            status = STATUS_FAILED;
            /*Only required in case of secure_elemnt/SPI interface*/
            if(mchannel->doeSE_Reset != NULL) {
              /*Hard reset of recovery*/
              mchannel->doeSE_Reset();
              usleep(100*1000);
            }
            /*Followed by interface reset to restart UAI
             * and MW context reset(SPI) & power recycle
             * in SMB*/
            mchannel->doeSE_JcopDownLoadReset();
        }
    }
    LOG(INFO) << StringPrintf("%s: exit; status = 0x%X", fn, status);
    return status;
}
/*******************************************************************************
**
** Function:        GetInfo
**
** Description:     Get the JCOP OS info
**
** Returns:         Success if ok.
**
*******************************************************************************/
tJBL_STATUS JcopOsDwnld::GetInfo(JcopOs_ImageInfo_t* pImageInfo, tJBL_STATUS status, JcopOs_TranscieveInfo_t* pTranscv_Info)
{
    static const char fn [] = "JcopOsDwnld::GetInfo";

    bool stat = false;
    IChannel_t *mchannel = gpJcopOs_Dwnld_Context->channel;
    int32_t recvBufferActualSize = 0;

    LOG(INFO) << StringPrintf("%s: enter;", fn);

    if(pTranscv_Info == NULL ||
       pImageInfo == NULL)
    {
      LOG(INFO) << StringPrintf("%s: Invalid parameter", fn);
      status = STATUS_FAILED;
    }
    else
    {
        memcpy(pImageInfo->fls_path, (char *)path[pImageInfo->index],
                 strlen(path[pImageInfo->index]) + 1);

        memset(pTranscv_Info->sSendData, 0, JCOP_MAX_BUF_SIZE);
        pTranscv_Info->timeout = gTransceiveTimeout;
        if(isUaiEnabled)
        {
             pTranscv_Info->sSendlength = (uint32_t)sizeof(Uai_GetInfo_APDU);
             memcpy(pTranscv_Info->sSendData, Uai_GetInfo_APDU, pTranscv_Info->sSendlength);
        }else
        {
            pTranscv_Info->sSendlength = (uint32_t)sizeof(GetInfo_APDU);
            memcpy(pTranscv_Info->sSendData, GetInfo_APDU, pTranscv_Info->sSendlength);
        }
        pTranscv_Info->sRecvlength = 1024;

        LOG(INFO) << StringPrintf("%s: Calling Secure Element Transceive", fn);
        stat = mchannel->transceive (pTranscv_Info->sSendData,
                                pTranscv_Info->sSendlength,
                                pTranscv_Info->sRecvData,
                                pTranscv_Info->sRecvlength,
                                recvBufferActualSize,
                                pTranscv_Info->timeout);
        if (stat != true)
        {
            status = STATUS_FAILED;
            pImageInfo->index =0;
            LOG(ERROR) << StringPrintf("%s: SE transceive failed status = 0x%X", fn, status);//Stop JcopOs Update
        }
        else if((pTranscv_Info->sRecvData[recvBufferActualSize-2] == 0x90) &&
                (pTranscv_Info->sRecvData[recvBufferActualSize-1] == 0x00))
        {
          SetUAI_Data(pImageInfo, pTranscv_Info->sRecvData);

          memcpy(pImageInfo->fls_path, path[pImageInfo->index],
                 strlen(path[pImageInfo->index]) + 1);

          pImageInfo->index++;
          status = STATUS_OKAY;

          LOG(INFO) << StringPrintf("%s: GetInfo Transceive status = 0x%X", fn,
                                    status);
        }
        else if((pTranscv_Info->sRecvData[recvBufferActualSize-2] == 0x6A) &&
                (pTranscv_Info->sRecvData[recvBufferActualSize-1] == 0x82) &&
                 pImageInfo->version_info.ver_status == STATUS_UPTO_DATE)
        {
            status = STATUS_UPTO_DATE;
        }
        else
        {
            status = STATUS_FAILED;
            LOG(INFO) << StringPrintf("%s; Invalid response for GetInfo", fn);
        }
    }

    if (status == STATUS_FAILED)
    {
      LOG(INFO) << StringPrintf("%s; status failed, doing reset...", fn);
      mchannel->doeSE_JcopDownLoadReset();
    }
    LOG(INFO) << StringPrintf("%s: exit; status = 0x%X", fn, status);
    return status;
}
/*******************************************************************************
**
** Function:        load_JcopOS_image
**
** Description:     Used to update the JCOP OS
**                  Get Info function has to be called before this
**
** Returns:         Success if ok.
**
*******************************************************************************/
tJBL_STATUS JcopOsDwnld::load_JcopOS_image(JcopOs_ImageInfo_t *Os_info, tJBL_STATUS status, JcopOs_TranscieveInfo_t *pTranscv_Info)
{
    static const char fn [] = "JcopOsDwnld::load_JcopOS_image";
    bool stat = false;
    int wResult;
    int32_t wIndex,wCount=0;
    int32_t wLen;

    IChannel_t *mchannel = gpJcopOs_Dwnld_Context->channel;
    int32_t recvBufferActualSize = 0;
    LOG(INFO) << StringPrintf("%s: enter", fn);
    if(Os_info == NULL ||
       pTranscv_Info == NULL)
    {
        LOG(ERROR) << StringPrintf("%s: invalid parameter", fn);
        return status;
    }
    Os_info->fp = fopen(Os_info->fls_path, "r");

    if (Os_info->fp == NULL) {
        LOG(ERROR) << StringPrintf("Error opening OS image file <%s> for reading: %s",
                    Os_info->fls_path, strerror(errno));
        return STATUS_FILE_NOT_FOUND;
    }
    wResult = fseek(Os_info->fp, 0L, SEEK_END);
    if (wResult) {
        LOG(ERROR) << StringPrintf("Error seeking end OS image file %s", strerror(errno));
        goto exit;
    }
    Os_info->fls_size = ftell(Os_info->fp);
    if (Os_info->fls_size < 0) {
        LOG(ERROR) << StringPrintf("Error ftelling file %s", strerror(errno));
        goto exit;
    }
    wResult = fseek(Os_info->fp, 0L, SEEK_SET);
    if (wResult) {
        LOG(ERROR) << StringPrintf("Error seeking start image file %s", strerror(errno));
        goto exit;
    }
    while(!feof(Os_info->fp))
    {
        LOG(ERROR) << StringPrintf("%s; Start of line processing", fn);

        wIndex=0;
        wLen=0;
        wCount=0;
        memset(pTranscv_Info->sSendData,0x00,JCOP_MAX_BUF_SIZE);
        pTranscv_Info->sSendlength=0;

        LOG(ERROR) << StringPrintf("%s; wIndex = 0", fn);
        for(wCount =0; (wCount < 5 && !feof(Os_info->fp)); wCount++, wIndex++)
        {
            wResult = FSCANF_BYTE(Os_info->fp,"%2X",&pTranscv_Info->sSendData[wIndex]);
        }
        if(wResult != 0)
        {
            wLen = pTranscv_Info->sSendData[4];
            LOG(ERROR) << StringPrintf("%s; Read 5byes success & len=%d", fn,wLen);
            if(wLen == 0x00)
            {
                LOG(ERROR) << StringPrintf("%s: Extended APDU", fn);
                wResult = FSCANF_BYTE(Os_info->fp,"%2X",&pTranscv_Info->sSendData[wIndex++]);
                wResult = FSCANF_BYTE(Os_info->fp,"%2X",&pTranscv_Info->sSendData[wIndex++]);
                wLen = ((pTranscv_Info->sSendData[5] << 8) | (pTranscv_Info->sSendData[6]));
            }
            for(wCount =0; (wCount < wLen && !feof(Os_info->fp)); wCount++, wIndex++)
            {
                wResult = FSCANF_BYTE(Os_info->fp,"%2X",&pTranscv_Info->sSendData[wIndex]);
            }
        }
        else
        {
            LOG(ERROR) << StringPrintf("%s: JcopOs image Read failed", fn);
            goto exit;
        }

        pTranscv_Info->sSendlength = wIndex;
        LOG(ERROR) << StringPrintf("%s: start transceive for length %d", fn, pTranscv_Info->sSendlength);
        if((pTranscv_Info->sSendlength != 0x03) &&
           (pTranscv_Info->sSendData[0] != 0x00) &&
           (pTranscv_Info->sSendData[1] != 0x00))
        {

            stat = mchannel->transceive(pTranscv_Info->sSendData,
                                    pTranscv_Info->sSendlength,
                                    pTranscv_Info->sRecvData,
                                    pTranscv_Info->sRecvlength,
                                    recvBufferActualSize,
                                    pTranscv_Info->timeout);
        }
        else
        {
            LOG(ERROR) << StringPrintf("%s: Invalid packet", fn);
            continue;
        }
        if(stat != true)
        {
            LOG(ERROR) << StringPrintf("%s: Transceive failed; status=0x%X", fn, stat);
            status = STATUS_FAILED;
            goto exit;
        }
        else if(recvBufferActualSize != 0 &&
                pTranscv_Info->sRecvData[recvBufferActualSize-2] == 0x90 &&
                pTranscv_Info->sRecvData[recvBufferActualSize-1] == 0x00)
        {
            //LOG(ERROR) << StringPrintf("%s: END transceive for length %d", fn, pTranscv_Info->sSendlength);
            status = STATUS_SUCCESS;
        }
        else if(pTranscv_Info->sRecvData[recvBufferActualSize-2] == 0x6F &&
                pTranscv_Info->sRecvData[recvBufferActualSize-1] == 0x00)
        {
            LOG(ERROR) << StringPrintf("%s: JcopOs is already upto date-No update required exiting", fn);
            Os_info->version_info.ver_status = STATUS_UPTO_DATE;
            status = STATUS_FAILED;
            break;
        }
        else if(pTranscv_Info->sRecvData[recvBufferActualSize-2] == 0x6F &&
                pTranscv_Info->sRecvData[recvBufferActualSize-1] == 0xA1)
        {
            LOG(ERROR) << StringPrintf("%s: JcopOs is already up to date-No update required exiting", fn);
            Os_info->version_info.ver_status = STATUS_UPTO_DATE;
            status = STATUS_UPTO_DATE;
            break;
        }
        else
        {
            status = STATUS_FAILED;
            LOG(ERROR) << StringPrintf("%s: Invalid response", fn);
        }
        LOG(ERROR) << StringPrintf("%s: Going for next line", fn);
    }

    if(status == STATUS_SUCCESS)
    {
        Os_info->cur_state++;
        /*If Patch Update is required*/
        if(isPatchUpdate)
        {
          /*Set the step to 3 to handle multiple
          JCOP Patch update*/
          Os_info->cur_state = 3;
        }
        SetJcopOsState(Os_info, Os_info->cur_state);
    }

exit:
    mchannel->doeSE_JcopDownLoadReset();
    LOG(ERROR) << StringPrintf("%s close fp and exit; status= 0x%X", fn,status);
    wResult = fclose(Os_info->fp);
    return status;
}

/*******************************************************************************
**
** Function:        GetJcopOsState
**
** Description:     Used to update the JCOP OS state
**
** Returns:         Success if ok.
**
*******************************************************************************/
tJBL_STATUS
JcopOsDwnld::GetJcopOsState(JcopOs_ImageInfo_t *Os_info, uint8_t *counter,
                            JcopOs_TranscieveInfo_t *pTranscv_Info) {
  static const char fn[] = "JcopOsDwnld::GetJcopOsState";
  tJBL_STATUS status = STATUS_SUCCESS;
  FILE *fp;
  uint8_t xx = 0;
  LOG(INFO) << StringPrintf("%s: enter", fn);
  IChannel_t *mchannel = gpJcopOs_Dwnld_Context->channel;
  if (Os_info == NULL) {
    LOG(ERROR) << StringPrintf("%s: invalid parameter", fn);
    return STATUS_FAILED;
  }
  fp = fopen(JCOP_INFO_PATH[mchannel->getInterfaceInfo()], "r");

  if (fp == NULL) {
    LOG(ERROR) << StringPrintf(
        "file <%s> not exits for reading- creating new file: %s",
        JCOP_INFO_PATH[mchannel->getInterfaceInfo()], strerror(errno));
    fp = fopen(JCOP_INFO_PATH[mchannel->getInterfaceInfo()], "w+");
    if (fp == NULL) {
      LOG(ERROR) << StringPrintf(
          "Error opening OS image file <%s> for reading: %s",
          JCOP_INFO_PATH[mchannel->getInterfaceInfo()], strerror(errno));
      return STATUS_FAILED;
    }
    fprintf(fp, "%u", xx);
    fclose(fp);
  } else {
    if (FSCANF_BYTE(fp, "%u", &xx) == 0) {
      LOG(ERROR) << StringPrintf("Failed in fscanf function");
    }
    LOG(ERROR) << StringPrintf("JcopOsState %d", xx);
    fclose(fp);
  }

  status = Get_UAI_JcopOsState(Os_info, &xx, pTranscv_Info);
  if (status != STATUS_SUCCESS) {
    if (status == STATUS_UPTO_DATE) {
      LOG(INFO) << StringPrintf("Jcop already upto date");
    } else {
      LOG(INFO) << StringPrintf("Error in getting DeriveJcopOsu_State info");
    }
    return status;
  }

  switch (xx) {
  case JCOP_UPDATE_STATE0:
  case JCOP_UPDATE_STATE3:
    LOG(ERROR) << StringPrintf("Starting update from UAI Authentication");
    Os_info->index = JCOP_UPDATE_STATE0;
    Os_info->cur_state = JCOP_UPDATE_STATE0;
    *counter = OSU_UAI_TRIGGER_STATE;
    break;
  case JCOP_UPDATE_STATE1:
    LOG(ERROR) << StringPrintf("Starting update from step2");
    Os_info->index = JCOP_UPDATE_STATE1;
    Os_info->cur_state = JCOP_UPDATE_STATE1;
    *counter = OSU_GETINFO_STATE2;
    break;
  case JCOP_UPDATE_STATE2:
    LOG(ERROR) << StringPrintf("Starting update from step3");
    Os_info->index = JCOP_UPDATE_STATE2;
    Os_info->cur_state = JCOP_UPDATE_STATE2;
    *counter = OSU_GETINFO_STATE3;
    break;
  case JCOP_UPDATE_STATE_TRIGGER_APDU:
    LOG(ERROR) << StringPrintf("Starting update from step1");
    Os_info->index = JCOP_UPDATE_STATE0;
    Os_info->cur_state = JCOP_UPDATE_STATE0;
    *counter = OSU_GETINFO_STATE1;
    break;
  default:
    LOG(ERROR) << StringPrintf("invalid state");
    status = STATUS_FAILED;
    break;
  }

  return status;
}

/*******************************************************************************
**
** Function:        SetJcopOsState
**
** Description:     Used to set the JCOP OS state
**
** Returns:         Success if ok.
**
*******************************************************************************/
tJBL_STATUS JcopOsDwnld::SetJcopOsState(JcopOs_ImageInfo_t *Os_info, uint8_t state)
{
    static const char fn [] = "JcopOsDwnld::SetJcopOsState";
    tJBL_STATUS status = STATUS_FAILED;
    FILE *fp;
    LOG(INFO) << StringPrintf("%s: enter", fn);
    IChannel_t *mchannel = gpJcopOs_Dwnld_Context->channel;
    if(Os_info == NULL)
    {
        LOG(ERROR) << StringPrintf("%s: invalid parameter", fn);
        return status;
    }
    fp = fopen(JCOP_INFO_PATH[mchannel->getInterfaceInfo()], "w");

    if (fp == NULL) {
      LOG(ERROR) << StringPrintf("Error opening OS image file <%s> for reading: %s",
        JCOP_INFO_PATH[mchannel->getInterfaceInfo()], strerror(errno));
    }
    else
    {
      fprintf(fp, "%u", state);
      fflush(fp);
      LOG(INFO) << StringPrintf("Current JcopOsState: %d", state);
      status = STATUS_SUCCESS;
      int fd = fileno(fp);
      int ret = fdatasync(fd);
      LOG(INFO) << StringPrintf("ret value: %d", ret);
      fclose(fp);
    }
    return status;
}

/*******************************************************************************
**
** Function:        Get_UAI_JcopOsState
**
** Description:     Get OSU state based on UAI query info
**
** Returns:         Success if ok.
**
*******************************************************************************/
tJBL_STATUS
JcopOsDwnld::Get_UAI_JcopOsState(JcopOs_ImageInfo_t *Os_info,
                                 uint8_t *dh_osu_state,
                                 JcopOs_TranscieveInfo_t *pTranscv_Info) {
  static const char fn[] = "JcopOsDwnld::Get_UAI_JcopOsState";
  tJBL_STATUS status = STATUS_SUCCESS;
  IChannel_t *mchannel = gpJcopOs_Dwnld_Context->channel;

  if (!isUaiEnabled)
    return status;

  status = GetInfo(Os_info, status, pTranscv_Info);
  if (status != STATUS_SUCCESS) {
    LOG(ERROR) << StringPrintf("%s: Get UAI query Info failed", fn);
    return status;
  } else {
    status = DeriveJcopOsu_State(Os_info, dh_osu_state);
  }

  mchannel->doeSE_JcopDownLoadReset();
  return status;
}

/*******************************************************************************
**
** Function:        SetUAI_Data
**
** Description:     Update UAI info in OSU structure
**
** Returns:         None.
**
*******************************************************************************/
void JcopOsDwnld::SetUAI_Data(JcopOs_ImageInfo_t *Os_info, uint8_t *pData) {
  Os_info->uai_info.CSNData =
      (pData[JCOP_UAI_CSN_INDEX] << 8 | pData[JCOP_UAI_CSN_INDEX + 1]);
  Os_info->uai_info.RSNData =
      (pData[JCOP_UAI_RSN_INDEX] << 8 | pData[JCOP_UAI_RSN_INDEX + 1]);
  Os_info->uai_info.FSNData =
      (pData[JCOP_UAI_FSN_INDEX] << 8 | pData[JCOP_UAI_FSN_INDEX + 1]);
  Os_info->uai_info.OSIDData =
      (pData[JCOP_UAI_OSID_INDEX] << 8 | pData[JCOP_UAI_OSID_INDEX + 1]);
}

/*******************************************************************************
**
** Function:        DeriveOsu_State
**
** Description:     Used to derive the actual OSU state based on UAI query info
**                  It compares DH state and updates in case of mismatch
**
** Returns:         Success if ok.
**
*******************************************************************************/
tJBL_STATUS JcopOsDwnld::DeriveJcopOsu_State(JcopOs_ImageInfo_t *Os_info,
                                             uint8_t *dh_osu_state) {
  static const char fn[] = "JcopOsDwnld::DeriveJcopOsu_State";
  tJBL_STATUS status = STATUS_SUCCESS;
  uint16_t usCSN = 0;
  uint16_t usRSN = 0;
  uint16_t usFSN = 0;
  uint16_t usUAI_OSID = OSID_0;
  uint8_t jcop_osu_state = OSID_0;

  usCSN = Os_info->uai_info.CSNData;
  usRSN = Os_info->uai_info.RSNData;
  usFSN = Os_info->uai_info.FSNData;
  usUAI_OSID = Os_info->uai_info.OSIDData;

  if (usUAI_OSID == OSID_JCOP) {
    jcop_osu_state = JCOP_UPDATE_STATE0;
  } else {
    if (usUAI_OSID == OSID_1 && usCSN == usRSN) {
      jcop_osu_state = JCOP_UPDATE_STATE_TRIGGER_APDU;
    } else if ((usUAI_OSID == OSID_2) && (usCSN == usRSN ||
               (usCSN == (usFSN - 2)))) {
      jcop_osu_state = JCOP_UPDATE_STATE1;
    } else if ((usUAI_OSID == OSID_SU1 && usCSN == usRSN) ||
               (usCSN == (usFSN - 1))) {
      jcop_osu_state = JCOP_UPDATE_STATE2;
    } else {
      LOG(ERROR) << StringPrintf("%s: Invalid data in query info shall retry",
                                 fn);
      return STATUS_FAILED;
    }
  }
  LOG(INFO) << StringPrintf("%s: JCOP OSU state = %d ", fn, jcop_osu_state);

  if (*dh_osu_state != jcop_osu_state) {

    if ((*dh_osu_state == JCOP_UPDATE_STATE2) &&
        (jcop_osu_state == JCOP_UPDATE_STATE0)) {
      jcop_osu_state = JCOP_UPDATE_STATE3;
      SetJcopOsState(Os_info, jcop_osu_state);
      LOG(INFO) << StringPrintf("%s: JCOP Already up to date = %d ", fn,
                                jcop_osu_state);
      return STATUS_UPTO_DATE;
    }
    SetJcopOsState(Os_info, jcop_osu_state);
    *dh_osu_state = jcop_osu_state;
  } else {
    if (*dh_osu_state == JCOP_UPDATE_STATE0) {
      SetJcopOsState(Os_info, jcop_osu_state);
    }
  }
  return status;
}
