/*
 **
 ** Copyright 2020, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */
/******************************************************************************
 **
 ** The original Work has been changed by NXP.
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 ** http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 **
 ** Copyright 2022-2023, 2025 NXP
 **
 *********************************************************************************/
#define LOG_TAG "OmapiTransport"
#include "OmapiTransport.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iomanip>
#include <vector>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <hardware_legacy/power.h>

#define UNUSED_V(a) a = a
#define RESP_CHANNEL_NOT_AVAILABLE 0x6881

using android::base::StringPrintf;

namespace se_update_agent {

std::string const ESE_READER_PREFIX = "eSE";
constexpr const char omapiServiceName[] =
    "android.se.omapi.ISecureElementService/default";
constexpr const char kChannelWakelockName[] = "nxp_keymint_channel";

class SEListener : public ::aidl::android::se::omapi::BnSecureElementListener {
};

void OmapiTransport::BinderDiedCallback(void* cookie) {
  LOG(INFO) << "Received binder died. OMAPI Service died";
  auto thiz = static_cast<OmapiTransport*>(cookie);
  thiz->closeConnection();
}
bool OmapiTransport::initialize() {
  LOG(INFO) << "Initialize the secure element connection";

  // Get OMAPI vendor stable service handler
  ::ndk::SpAIBinder ks2Binder(AServiceManager_checkService(omapiServiceName));
  omapiSeService =
      aidl::android::se::omapi::ISecureElementService::fromBinder(ks2Binder);

  if (omapiSeService == nullptr) {
    LOG(ERROR) << "Failed to start omapiSeService null";
    return false;
  }
  AIBinder_linkToDeath(omapiSeService->asBinder().get(), mDeathRecipient.get(),
                       this);

  // reset readers, clear readers if already existing
  if (mVSReaders.size() > 0) {
    closeConnection();
  }

  std::vector<std::string> readers = {};
  // Get available readers
  auto status = omapiSeService->getReaders(&readers);
  if (!status.isOk()) {
    LOG(ERROR) << "getReaders failed to get available readers: "
               << status.getMessage();
    return false;
  }

  // Get SE readers handlers
  for (auto& readerName : readers) {
    std::shared_ptr<::aidl::android::se::omapi::ISecureElementReader> reader;
    status = omapiSeService->getReader(readerName, &reader);
    if (!status.isOk()) {
      LOG(ERROR) << "getReader for " << readerName.c_str()
                 << " Failed: " << status.getMessage();
      return false;
    }

    mVSReaders[readerName] = std::move(reader);
  }

  // Find eSE reader, as of now assumption is only eSE available on device
  LOG(INFO) << "Finding eSE reader";
  eSEReader = nullptr;
  if (mVSReaders.size() > 0) {
    for (const auto& [name, reader] : mVSReaders) {
      if (name.find(ESE_READER_PREFIX, 0) != std::string::npos) {
        LOG(DEBUG) << "eSE reader found: " << name;
        eSEReader = reader;
        std::string prefTerminalName = "eSE1";
        if (name.compare(prefTerminalName) == 0x00) {
          LOG(INFO) << "Found reader " << prefTerminalName << " breaking.";
          break;
        }
      }
    }
  }

  if (eSEReader == nullptr) {
    LOG(ERROR) << "secure element reader " << ESE_READER_PREFIX << " not found";
    return false;
  }
  // Get ATR
  bool ese_reader_status = false;
  auto res = eSEReader->isSecureElementPresent(&ese_reader_status);
  if (!res.isOk()) {
    LOG(ERROR) << "isSecureElementPresent error: " << res.getMessage();
  }
  if (!ese_reader_status) {
    LOG(ERROR) << "secure element not found";
  }

  if (session == nullptr ||
      ((session->isClosed(&ese_reader_status).isOk() && ese_reader_status))) {
    res = eSEReader->openSession(&session);
    if (!res.isOk()) {
      LOG(ERROR) << "openSession error: " << res.getMessage();
    }
    if (session == nullptr) {
      LOG(ERROR) << "Could not open session null";
    } else {
      res = session->getAtr(&mAtr);
      if (!res.isOk()) {
        LOG(ERROR) << "Failed to get ATR";
      }
      session->close();
      session = nullptr;
    }
  }
  return true;
}

bool OmapiTransport::openConnection() {
  // if already conection setup done, no need to initialise it again.
  if (isConnected()) {
    return true;
  }

  return initialize();
}

bool OmapiTransport::sendData(const vector<uint8_t>& inData,
                              vector<uint8_t>& output) {
  std::vector<uint8_t> apdu(inData);
  if (!isConnected()) {
    // Try to initialize connection to eSE
    LOG(INFO) << "Not connected, try to initialize connection to OMAPI";
    if (!initialize()) {
      LOG(ERROR) << "Failed to connect to OMAPI";
      closeConnection();
      return false;
    }
  }

  if (inData.size() == 0x00) {
    LOG(ERROR) << "Failed to send data, APDU is null";
    return false;
  }

  if (eSEReader != nullptr) {
    LOG(DEBUG) << "Sending apdu data to secure element: " << ESE_READER_PREFIX;

    acquire_wake_lock(PARTIAL_WAKE_LOCK, kChannelWakelockName);
    bool status = false;
    if (session == nullptr) {
      LOG(ERROR) << "session is null";
      return false;
    }
    if (session->isClosed(&status).isOk() && status) {
      LOG(ERROR) << "session is closed";
      return false;
    }

    if (channel == nullptr) {
      LOG(ERROR) << "channel is null";
      return false;
    }

    auto res = channel->transmit(apdu, &output);

    if (!res.isOk()) {
      LOG(ERROR) << "transmit error: " << res.getMessage();
      return false;
    }
    release_wake_lock(kChannelWakelockName);
  } else {
    LOG(ERROR) << "secure element reader " << ESE_READER_PREFIX << " not found";
    return false;
  }
  return true;
}

void OmapiTransport::closeConnection() {
  LOG(ERROR) << "Closing all connections";
  if (omapiSeService != nullptr) {
    if (mVSReaders.size() > 0) {
      for (const auto& [name, reader] : mVSReaders) {
        reader->closeSessions();
      }
      mVSReaders.clear();
    }
  }
  if (omapiSeService != nullptr) {
    AIBinder_unlinkToDeath(omapiSeService->asBinder().get(),
                           mDeathRecipient.get(), this);
    omapiSeService = nullptr;
  }
  session = nullptr;
  channel = nullptr;
}

bool OmapiTransport::isConnected() {
  // Check already initialization completed or not
  if (omapiSeService != nullptr && eSEReader != nullptr) {
    LOG(DEBUG) << "Connection initialization already completed";
    return true;
  }
  LOG(DEBUG) << "Connection initialization not completed";
  return false;
}

bool OmapiTransport::closeChannel(uint8_t channel_num) {
  LOG(INFO) << "Omapi: Closing channel number: " << channel_num;
  if (channel != nullptr) channel->close();
  LOG(INFO) << "Channel closed";
  return true;
}

bool OmapiTransport::openChannel(std::vector<uint8_t>& aid, int8_t& channel_num,
                                 std::vector<uint8_t>& select_resp) {
  auto mSEListener = ndk::SharedRefBase::make<SEListener>();
  if (eSEReader == nullptr) {
    LOG(ERROR) << "eSE reader is null";
    return false;
  }

  bool status = false;
  auto res = eSEReader->isSecureElementPresent(&status);
  if (!res.isOk()) {
    LOG(ERROR) << "isSecureElementPresent error: " << res.getMessage();
    return false;
  }
  if (!status) {
    LOG(ERROR) << "secure element not found";
    return false;
  }

  if (session == nullptr || ((session->isClosed(&status).isOk() && status))) {
    res = eSEReader->openSession(&session);
    if (!res.isOk()) {
      LOG(ERROR) << "openSession error: " << res.getMessage();
      return false;
    }
    if (session == nullptr) {
      LOG(ERROR) << "Could not open session null";
      return false;
    }
  }
  if ((channel == nullptr || (channel->isClosed(&status).isOk() && status))) {
    auto res = session->openLogicalChannel(aid, 0x00, mSEListener, &channel);
    if (!res.isOk()) {
      LOG(ERROR) << "openLogicalChannel error: " << res.getMessage();
      // Assume Applet selection Fail
      select_resp.push_back(APP_NOT_FOUND_SW1);
      select_resp.push_back(APP_NOT_FOUND_SW2);
      return false;
    }
    if (channel == nullptr) {
      LOG(ERROR) << "Could not open channel null";
      select_resp.push_back(0xFF);
      select_resp.push_back(0xFF);
      return false;
    }

    res = channel->getSelectResponse(&select_resp);
    if (!res.isOk()) {
      LOG(ERROR) << "getSelectResponse error: " << res.getMessage();
      return false;
    }
    if ((select_resp.size() < 2) ||
        ((select_resp[select_resp.size() - 1] & 0xFF) != 0x00) ||
        ((select_resp[select_resp.size() - 2] & 0xFF) != 0x90)) {
      LOG(ERROR) << "Failed to select the Applet.";
      return false;
    }
    // opened channel succesfully
    channel_num = 0;  // fixed channel number
  }
  return true;
}

void OmapiTransport::getAtr(std::vector<uint8_t>& atr) { atr = this->mAtr; }
}  // namespace se_update_agent
