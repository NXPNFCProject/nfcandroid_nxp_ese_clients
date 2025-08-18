/******************************************************************************
 *
 *  Copyright 2018-2020, 2023, 2025 NXP
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

#include "SEUpdaterClient.h"
#include <Utils.h>
#include "SEConnection.h"
#include "ScriptMetadataParser.h"

#include <IChannel.h>
#include <LsClient.h>
#include <android-base/properties.h>
#include <log/log.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <iomanip>
#include <iostream>
#include <thread>
#include <vector>

#define MAX_RETRY_LOAD 3
constexpr char SEMS_SELF_UPDATE_DIR_NAME[] = "sems_self_update";
static TransportType current_transport = TransportType::HAL_TO_OMAPI;
IChannel_t Ch;
ese_update_state_t ese_update = ESE_UPDATE_COMPLETED;
constexpr char kEseLoadPendingProp[] = "vendor.se_update_agent.load_pending";
constexpr char kEseLoadRetryCountProp[] =
    "persist.vendor.se_update_agent.load_retry_cnt";

void CheckAndApplyUpdate(const std::string& script_dir_path);
static SESTATUS ApplyUpdate(ExecutionState exe_state);
static SESTATUS ExecuteSemsScript(const char* script_path,
                                  std::streampos start_offset,
                                  ExecutionState exec_state);
void seteSEClientState(uint8_t state);
static SESTATUS GetInterruptedScriptPath(std::string& interrupted_script_path,
                                         std::streampos& start_offset,
                                         ExecutionState exe_state);
#ifdef NXP_BOOTTIME_UPDATE
void* eSEClientUpdate_ThreadHandler(void* data);
void* eSEUpdate_SE_SeqHandler(void* data);
void eSEClientUpdate_Thread(const char* path);
#endif  // NXP_BOOTTIME_UPDATE
SESTATUS ESE_ChannelInit(IChannel* ch);
uint8_t performLSUpdate(const char* path, std::streampos start_offset);
SESTATUS eSEUpdate_SeqHandler(const char* path, std::streampos start_offset);

void SE_Reset() { /* phNxpEse_coldReset(); */ }

int16_t SE_Open() {
  // connect to eSEHAL or OMAPI based on transport type
  ALOGD("SE_Open: initiliaze connection to eSEHAL");
  SEConnection::getInstance(current_transport);
  return SESTATUS_OK;
}

SESTATUS InitializeConnection() {
  uint8_t retry = 0;
  const uint32_t MAX_RETRY_COUNT = 60;  // 60 secs
  while (retry++ < MAX_RETRY_COUNT) {
    if (!SEConnection::getInstance(current_transport).initialize()) {
      ALOGD("Failed to initailize eSEHAL. Retrying(%d/%d) after 1 sec", retry,
            MAX_RETRY_COUNT);
      std::this_thread::sleep_for(
          std::chrono::milliseconds(1000));  // re-try every 1 sec
    } else {
      return SESTATUS_OK;
    }
  }
  return SESTATUS_FAILED;
}

bool SE_Transmit(uint8_t* xmitBuffer, int32_t xmitBufferSize,
                 uint8_t* recvBuffer, int32_t recvBufferMaxSize,
                 int32_t& recvBufferActualSize, int32_t timeoutMillisec) {
  bool result = false;

  std::vector<uint8_t> cmd_vec(xmitBuffer, xmitBuffer + xmitBufferSize);
  ALOGD("cmd_vec is %s", toString(cmd_vec).c_str());
  InitializeConnection();

  if (cmd_vec.size() >= 3 && cmd_vec[0] == 0x00 && cmd_vec[1] == 0xA4 &&
      cmd_vec[2] == 0x04) {
    std::vector<uint8_t> aid(xmitBuffer + 5, xmitBuffer + xmitBufferSize);
    ALOGD("OpenChannel for AID: %s", toString(aid).c_str());
    std::vector<uint8_t> select_resp = {};
    int8_t channel_num = -1;
    SEConnection::getInstance().transport_->openChannel(aid, channel_num,
                                                        select_resp);
    if (channel_num != -1) {
      recvBuffer[0] = channel_num;
      memcpy(&recvBuffer[1], &select_resp[0], select_resp.size());
      recvBufferActualSize = select_resp.size() + 1;
      ALOGD("Select AID Response: %s", toString(select_resp).c_str());
      ALOGD("Channel number for select AID: %d", static_cast<int>(channel_num));
      result = true;
    } else {
      memcpy(&recvBuffer[0], &select_resp[0], select_resp.size());
      recvBufferActualSize = select_resp.size();
      ALOGD("openLogicalChannel Failed");
    }
  } else if (cmd_vec.size() >= 5 && cmd_vec[1] == 0x70 && cmd_vec[2] == 0x80 &&
             cmd_vec[0] == cmd_vec[3]) {
    ALOGD("Close channel with channelId: %d",
          static_cast<uint32_t>(cmd_vec[0] & 0xFF));
    auto status =
        SEConnection::getInstance().transport_->closeChannel(cmd_vec[0]);
    recvBufferActualSize = 2;
    if (!status) {
      recvBuffer[0] = 0x64;
      recvBuffer[1] = 0xFF;
      ALOGD("Close channel failed for channelId: %d",
            static_cast<uint32_t>(cmd_vec[0] & 0xFF));
    } else {
      result = true;
      recvBuffer[0] = 0x90;
      recvBuffer[1] = 0x00;
    }
  } else {
    std::vector<uint8_t> resp_vec;
    auto status =
        SEConnection::getInstance().transport_->sendData(cmd_vec, resp_vec);
    if (status) {
      memcpy(&recvBuffer[0], &resp_vec[0], resp_vec.size());
      recvBufferActualSize = resp_vec.size();
      ALOGD("resp_vec is %s", toString(resp_vec).c_str());
      result = true;
    } else {
      result = false;
    }
  }
  ALOGD("%s: recBufferActualsize = 0x%x ", __FUNCTION__, recvBufferActualSize);
  return true;
}

void SE_JcopDownLoadReset() { /*phNxpEse_resetJcopUpdate();*/ }

bool SE_Close(int16_t mHandle) {
  // TODO : correct usage of this method
  if (mHandle != 0)
    return true;
  else
    return false;
}

bool SE_parse_response(uint8_t* recvBuffer, int32_t recvBuffersize) {
  return ParseResponse(recvBuffer, recvBuffersize);
}
#ifdef NXP_BOOTTIME_UPDATE
/***************************************************************************
**
** Function:        checkEseClientUpdate
**
** Description:     Check the initial condition
                    and interface for eSE Client update for LS and JCOP download
**
** Returns:         SUCCESS of ok
**
*******************************************************************************/
void checkEseClientUpdate() {
  ALOGD("%s enter:  ", __func__);
  seteSEClientState(ESE_UPDATE_STARTED);
}

/***************************************************************************
**
** Function:        perform_eSEClientUpdate
**
** Description:     Perform LS download during early boot
**
** Returns:         SUCCESS / SESTATUS_FAILED
**
*******************************************************************************/
SESTATUS perform_eSEClientUpdate() {
  ALOGD("%s enter:  ", __func__);
  eSEClientUpdate_Thread("/vendor/etc/loaderservice_updater.txt");
  return SESTATUS_OK;
}
#endif  // NXP_BOOTTIME_UPDATE

static SESTATUS ExecuteSemsScript(const char* script_path,
                                  std::streampos start_offset,
                                  ExecutionState exec_state) {
  seteSEClientState(ESE_LS_UPDATE_REQUIRED);
  SetScriptExecutionState(exec_state);
  auto status = eSEUpdate_SeqHandler(script_path, start_offset);
  if (status != SESTATUS_OK) {
    ALOGE("Failed: SEMS execution for: %s, Retrying", script_path);
    // re-try one time
    seteSEClientState(ESE_LS_UPDATE_REQUIRED);
    SetScriptExecutionState(exec_state);
    std::string interrupted_script_path;
    std::streampos start_offset = 0;  // default start from beginning
    // find the start_offset
    GetInterruptedScriptPath(interrupted_script_path, start_offset, exec_state);
    status = eSEUpdate_SeqHandler(script_path, start_offset);
  }
  return status;
}

// Fetch last SEMS script execution status
static SESTATUS getLastScriptExecutionState(
    bool* is_interrupted, std::vector<uint8_t>& auth_frame_signature) {
  uint8_t status = SESTATUS_FAILED;
  const uint8_t INS_GET_DATA = 0xCA;

  // SEMS execution status
  const uint8_t P2_EXE_STATUS = 0x46;

  // Authentication frame signature of the last executed script
  const uint8_t P2_GET_AUTH_FRAME_SIGN = 0x47;

  ESE_ChannelInit(&Ch);

  ALOGE("%s : select SEMS", __FUNCTION__);
  status = LsClient_SemsSelect(&Ch);
  if (status != SESTATUS_OK) {
    *is_interrupted = false;
    return static_cast<SESTATUS>(status);
  }
  std::vector<uint8_t> resp_vec;

  status = LsClient_SemsSendGetDataCmd(INS_GET_DATA, P2_EXE_STATUS, resp_vec);
  if (status == SESTATUS_OK) {
    uint32_t resp_size = resp_vec.size();
    if (resp_size >= 3 && resp_vec[resp_size - 2] == 0x90 &&
        resp_vec[resp_size - 1] == 0x00) {
      // third byte from starting is the response code
      *is_interrupted = (resp_vec[2] == 0x01) ? true : false;
    }
    if (*is_interrupted) {
      resp_vec.resize(0);
      status = LsClient_SemsSendGetDataCmd(INS_GET_DATA, P2_GET_AUTH_FRAME_SIGN,
                                           resp_vec);
      if (status == SESTATUS_OK)
        auth_frame_signature.assign(&resp_vec[4], &resp_vec[4] + resp_vec[3]);
    }
  } else {
    ALOGE("%s : GETDATA CMD Failed", __FUNCTION__);
  }
  ALOGE("%s : De-select SEMS", __FUNCTION__);
  LsClient_SemsDeSelect();
  return static_cast<SESTATUS>(status);
}

static bool HasMatchingSignature(
    const std::vector<uint8_t>& interrupted_auth_frame,
    const std::vector<std::pair<std::vector<uint8_t>, std::streampos>>&
        auth_frames_in_script,
    std::streampos* script_start_offset) {
  for (const auto& auth_frame : auth_frames_in_script) {
    if (interrupted_auth_frame == auth_frame.first) {
      *script_start_offset = auth_frame.second;
      ALOGD("Interrupted Script auth frame found at offset %lld",
            static_cast<long long>(*script_start_offset));
      return true;
    }
  }

  return false;
}

static SESTATUS GetInterruptedScriptPath(std::string& interrupted_script_path,
                                         std::streampos& start_offset,
                                         ExecutionState exe_state) {
  bool sems_interrupted = false;
  std::vector<uint8_t> interrupted_sems_auth_frame_sign;
  auto status = getLastScriptExecutionState(&sems_interrupted,
                                            interrupted_sems_auth_frame_sign);
  const LoadUpdateScriptMetaInfo* interrupted_script = nullptr;
  if (sems_interrupted) {
    ALOGD("Execution was interrupted for script with signature: %s",
          toString(interrupted_sems_auth_frame_sign).c_str());
    auto all_scripts_info = GetEnumeratedScriptsData();

    for (const auto& current_script : all_scripts_info) {
      // check only for LOAD scripts
      if (HasMatchingSignature(interrupted_sems_auth_frame_sign,
                               current_script.load_script.signatures,
                               &start_offset)) {
        if (exe_state == ExecutionState::LOAD) {
          interrupted_script = &(current_script.load_script);
        } else {
          ALOGE("Not in required execution state Expected LOAD, Found %d",
                exe_state);
        }
        break;
      }
      if (HasMatchingSignature(interrupted_sems_auth_frame_sign,
                               current_script.update_script.signatures,
                               &start_offset)) {
        if (exe_state == ExecutionState::UPDATE) {
          interrupted_script = &(current_script.update_script);
        } else {
          ALOGE("Not in required execution state Expected UPDATE, Found %d",
                exe_state);
        }
        break;
      }
    }
    if (interrupted_script != nullptr &&
        hasSufficientESEMemoryForScript(*interrupted_script)) {
      interrupted_script_path = interrupted_script->script_path;
    }
  }
  return status;
}
static SESTATUS ParseSemsScriptsMetadataInternal(
    const std::string& script_dir_path, bool clear_version_table = true) {
  ParseMetadataError result =
      ParseSemsScriptsMetadata(script_dir_path, clear_version_table);
  if (result != ParseMetadataError::SUCCESS) {
    return SESTATUS_SCRIPT_PARSE_FAILURE;
  }
  if (InitializeConnection() != SESTATUS_OK) {
    return SESTATUS_FAILED;
  }

  std::vector<uint8_t> atr;
  SEConnection::getInstance().getAtr(atr);
  std::vector<uint8_t> chip_type(atr.begin(), atr.begin() + 5);

  result = FilterScriptsForChiptype(chip_type);
  if (result != ParseMetadataError::SUCCESS) {
    return SESTATUS_SCRIPT_PARSE_FAILURE;
  }

  return SESTATUS_OK;
}
// check and resume interrupted script execution

static SESTATUS ResumeInterruptedScript(const std::string& script_dir_path,
                                        ExecutionState exe_state) {
  auto status = ParseSemsScriptsMetadataInternal(script_dir_path);
  if (status != SESTATUS_OK) {
    return status;
  }
  auto getstatus_script_metadata = GetStatusScriptData();
  std::string interrupted_script_path;
  std::streampos start_offset = 0;  // default start from beginning
  GetInterruptedScriptPath(interrupted_script_path, start_offset, exe_state);
  if (!interrupted_script_path.empty()) {
    ALOGD("Resuming execution of interrupted script: %s at offset: %lld",
          interrupted_script_path.c_str(),
          static_cast<long long>(start_offset));
    status = ExecuteSemsScript(interrupted_script_path.c_str(), start_offset,
                               exe_state);
    if (status != SESTATUS_OK) {
      ALOGE("Failed to resume execution of interrupted script");
    }
  }
  return status;
}

// wrapper function to know if applet load/update is required
SESTATUS CheckAppletUpdateRequired(bool* load_req, bool* update_req) {
  // compare currently installed versions with versions from SEMS scripts
  auto getstatus_script_metadata = GetStatusScriptData();
  auto status = ExecuteSemsScript(getstatus_script_metadata.script_path.c_str(),
                                  0, ExecutionState::GET_STATUS);
  if (status == SESTATUS_OK) CheckLoad_Or_UpdateRequired(load_req, update_req);
  return status;
}

/***************************************************************************
**
** Function:        PrepareUpdate
**
** Description:     Execute LOAD type SEMS script if required
**
** Returns:         void
**
*******************************************************************************/
SESTATUS PrepareUpdate(const std::string& script_dir_path, bool retry_load) {
  current_transport = TransportType::HAL_TO_OMAPI;

  if (SESTATUS_SCRIPT_PARSE_FAILURE ==
      ResumeInterruptedScript(script_dir_path, ExecutionState::LOAD)) {
    // no retry for parsing failure
    return SESTATUS_OK;
  }

  bool load_req = false, update_req = false;
  auto status = CheckAppletUpdateRequired(&load_req, &update_req);
  if (status != SESTATUS_OK) {
    ALOGE("Failed to check if update is required");
    return status;
  }
  if (!retry_load) {
    // LOAD triggered by OTA Agent
    // Reset retry counter to 0 so that if LOAD fails/tears here, it can be
    // retried at next boot by se_update_agent itself
    android::base::SetProperty(kEseLoadRetryCountProp, std::to_string(0));
  }
  if (load_req) {
    status = ApplyUpdate(ExecutionState::LOAD);
  } else {
    ALOGI("ELF LOAD is not required");
  }
  return status;
}
/***************************************************************************
**  function: PerformUpdate
**  description: Executes Sems script of type UPDATE
**  @arg1: dir path containing Sems scripts
**  @returns void
*******************************************************************************/

/***************************************************************************
**
** Function:        PerformUpdate
**
** Description:     Execute UPDATE type SEMS script if required
**
** Returns:         void
**
*******************************************************************************/

void PerformUpdate(const std::string& script_dir_path) {
  // check and resume if SEMS Self update was teared
  std::string sems_self_update_dir_path =
      script_dir_path + "/" + SEMS_SELF_UPDATE_DIR_NAME;

  current_transport = TransportType::HAL_TO_HAL;
  auto status_sems = ResumeInterruptedScript(sems_self_update_dir_path,
                                             ExecutionState::UPDATE);

  // check and resume if Other Applet(s) update was teared
  auto status_other =
      ResumeInterruptedScript(script_dir_path, ExecutionState::UPDATE);

  if (status_sems != SESTATUS_FILE_NOT_FOUND) {
    ALOGI("Check and apply updates for Sems Self Update");
    CheckAndApplyUpdate(sems_self_update_dir_path);
  }

  if (status_other != SESTATUS_FILE_NOT_FOUND) {
    ALOGI("Check and apply updates for other Applets");
    CheckAndApplyUpdate(script_dir_path);
  }
}

void CheckAndApplyUpdate(const std::string& script_dir_path) {
  current_transport = TransportType::HAL_TO_HAL;
  auto status = ParseSemsScriptsMetadataInternal(script_dir_path);
  if (status != SESTATUS_OK) {
    return;
  }
  bool load_req = false, update_req = false;
  status = CheckAppletUpdateRequired(&load_req, &update_req);
  if (status != SESTATUS_OK) {
    ALOGE("Failed to check if update is required");
    return;
  }
  if (update_req) {
    ApplyUpdate(ExecutionState::UPDATE);
  } else {
    ALOGI("ESE componenet(s) are up-to-date with scripts under %s",
          script_dir_path.c_str());
  }
}

void RetryPrepareUpdate(const std::string& script_dir_path) {
  std::string prop_value =
      android::base::GetProperty(kEseLoadPendingProp, /* default */ "0");
  if (prop_value.compare("1") == 0) {
    ALOGI("ELF load is pending");
    if (!android::base::SetProperty(kEseLoadPendingProp, "0")) {
      ALOGE("Failed to reset the property..exiting");
      return;
    }
  }
  auto retry_cnt =
      android::base::GetUintProperty<uint8_t>(kEseLoadRetryCountProp, 0);
  ALOGI("LOAD retry count: %d", retry_cnt);
  if (retry_cnt++ > MAX_RETRY_LOAD) {
    ALOGE("MAX Retry count reached for force LOAD.. exiting");
  } else {
    if (PrepareUpdate(script_dir_path, true) == SESTATUS_OK) {
      // reset retry counter
      retry_cnt = 0;
    }
    android::base::SetProperty(kEseLoadRetryCountProp,
                               std::to_string(retry_cnt));
  }
}

// Iterate over all parsed scripts and execute based on current execution state
SESTATUS ApplyUpdate(ExecutionState exe_state) {
  SESTATUS status = SESTATUS_OK;
  auto all_scripts_info = GetEnumeratedScriptsData();

  ALOGD("Display all scripts info after check update_required");
  DisplayAllScriptsInfo();

  std::string current_script_path;
  bool preload_pending = false;
  ALOGI("exe_state is %d", exe_state);
  for (const auto& current_script : all_scripts_info) {
    std::string script_path;
    switch (exe_state) {
      case ExecutionState::UPDATE:
        if (current_script.update_required &&
            current_script.update_script_exists) {
          if (current_script.pre_load_required) {
            ALOGE("pre_load is not completed for %s.. aborting",
                  current_script.update_script.script_path.c_str());
            preload_pending = true;
          } else if (hasSufficientESEMemoryForScript(
                         current_script.update_script)) {
            script_path = current_script.update_script.script_path;
          }
        }
        break;
      case ExecutionState::LOAD:
        if (current_script.pre_load_required &&
            current_script.load_script_exists &&
            hasSufficientESEMemoryForScript(current_script.load_script)) {
          script_path = current_script.load_script.script_path;
        }
        break;
      case ExecutionState::GET_STATUS:
        ALOGE("Un-Expected Execution state: GET_STATUS");
        break;
      default:
        ALOGE("state not recognized");
    }

    if (!script_path.empty()) {
      ALOGI("Start SEMS execution for script: %s", script_path.c_str());
      auto exec_status =
          ExecuteSemsScript(script_path.c_str(), 0 /*from start*/, exe_state);
      if (exec_status != SESTATUS_OK) {
        status = exec_status;
        ALOGE("Failed: SEMS execution for script: %s", script_path.c_str());
      } else {
        ALOGI("Execution completed successfully: %s", script_path.c_str());
      }
    }
  }
  if (preload_pending) {
    if (!android::base::SetProperty(kEseLoadPendingProp, "1")) {
      ALOGE("Failed to set the property");
    }
  }
  return status;
}

SESTATUS ESE_ChannelInit(IChannel* ch) {
  ch->open = SE_Open;
  ch->close = SE_Close;
  ch->transceive = SE_Transmit;
  ch->transceiveRaw = SE_Transmit;
  ch->doeSE_Reset = SE_Reset;
  ch->parse_response = SE_parse_response;
  return SESTATUS_OK;
}
#ifdef NXP_BOOTTIME_UPDATE
/*******************************************************************************
**
** Function:        eSEClientUpdate_Thread
**
** Description:    Wrapper funtion to start Updater thread
**
** Returns:         void
**
*******************************************************************************/
void eSEClientUpdate_Thread(const char* script_path) {
  pthread_t thread;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  if (pthread_create(&thread, &attr, &eSEClientUpdate_ThreadHandler,
                     (void*)script_path) != 0) {
    ALOGD("Thread creation failed");
  } else {
    ALOGD("Thread creation success");
  }
  // pthread_attr_destroy(&attr);
  ALOGD("waiting for thread to complete");
  pthread_join(thread, NULL);
  ALOGD("Thread execution completed");
}

/*******************************************************************************
**
** Function:        eSEClientUpdate_ThreadHandler
**
** Description:     Thread handler for ESE Update
**
** Returns:         none
**
*******************************************************************************/
void* eSEClientUpdate_ThreadHandler(void* data) {
  (void)data;
  int cnt = 0;
  const char* script_path = (char*)data;
  ALOGD("%s Enter\n", __func__);
  seteSEClientState(ESE_LS_UPDATE_REQUIRED);
  eSEUpdate_SeqHandler(script_path);
  ALOGD("%s Exit eSEClientUpdate_Thread\n", __func__);
  return NULL;
}
#endif  // NXP_BOOTTIME_UPDATE
/*******************************************************************************
**
** Function:        performLSUpdate
**
** Description:     Perform LS update
**
** Returns:         Sems execution status
**
*******************************************************************************/
uint8_t performLSUpdate(const char* path, std::streampos start_offset) {
  uint8_t status = ESE_ChannelInit(&Ch);
  if (status == SESTATUS_OK) {
    status = performLSDownload(&Ch, path, start_offset);
  }
  return status;
}
/*******************************************************************************
**
** Function:        seteSEClientState
**
** Description:     Function to set the eSEUpdate state
**
** Returns:         void
**
*******************************************************************************/
void seteSEClientState(uint8_t state) {
  ALOGE("%s: State = %d", __FUNCTION__, state);
  ese_update = (ese_update_state_t)state;
}
/*******************************************************************************
**
** Function:        eSEUpdate_SeqHandler
**
** Description:     ESE client update handler
**
** Returns:         SUCCESS of ok
**
*******************************************************************************/
SESTATUS eSEUpdate_SeqHandler(const char* path, std::streampos start_offset) {
  SESTATUS status = SESTATUS_FAILED;
  switch (ese_update) {
    case ESE_UPDATE_STARTED:
      [[fallthrough]];
    case ESE_LS_UPDATE_REQUIRED:
      status = (SESTATUS)performLSUpdate(path, start_offset);
      if (status != SESTATUS_OK) {
        ALOGE("%s: LS_UPDATE_FAILED", __FUNCTION__);
      }
      [[fallthrough]];
    case ESE_LS_UPDATE_COMPLETED:
      [[fallthrough]];
    case ESE_UPDATE_COMPLETED:
      seteSEClientState(ESE_UPDATE_COMPLETED);
      break;
  }
  return status;
}

/*******************************************************************************
**
** Function:        LogVersionInfo
**
** Description:     Gets version info for each applet from eSE and SEMS scripts
**                  and logs them in logcat
**
** Returns:         void
**
*******************************************************************************/

void LogVersionInfo(const std::string& script_dir_path) {
  std::string sems_self_update_dir_path =
      script_dir_path + "/" + SEMS_SELF_UPDATE_DIR_NAME;
  std::vector<std::string> update_pkg_path = {std::move(sems_self_update_dir_path),
                                              script_dir_path};

  current_transport = TransportType::HAL_TO_OMAPI;

  for (const auto& path : update_pkg_path) {
    auto status =
        ParseSemsScriptsMetadataInternal(path, false /*clear version table*/);
    if (status == SESTATUS_OK) {
      bool load_req = false, update_req = false;
      status = CheckAppletUpdateRequired(&load_req, &update_req);
      if (status != SESTATUS_OK) {
        ALOGE("Failed to check if update is required");
      }
    }
  }
  PrintVersionTable();
}
