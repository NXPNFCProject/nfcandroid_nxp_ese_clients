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
#pragma once

#include <aidl/android/se/omapi/BnSecureElementListener.h>
#include <aidl/android/se/omapi/ISecureElementChannel.h>
#include <aidl/android/se/omapi/ISecureElementListener.h>
#include <aidl/android/se/omapi/ISecureElementReader.h>
#include <aidl/android/se/omapi/ISecureElementService.h>
#include <aidl/android/se/omapi/ISecureElementSession.h>
#include <android/binder_manager.h>

#include <map>
#include <memory>
#include <vector>
#include "ITransport.h"

#define APP_NOT_FOUND_SW1 0x6A
#define APP_NOT_FOUND_SW2 0x82

namespace se_update_agent {
using std::shared_ptr;
using std::vector;

/**
 * OmapiTransport is derived from ITransport. This class gets the OMAPI service
 * binder instance and uses IPC to communicate with OMAPI service. OMAPI inturn
 * communicates with hardware via ISecureElement.
 */
class OmapiTransport : public ITransport {
 public:
  OmapiTransport()
      : omapiSeService(nullptr),
        eSEReader(nullptr),
        session(nullptr),
        channel(nullptr),
        mVSReaders({}) {
    mDeathRecipient = ::ndk::ScopedAIBinder_DeathRecipient(
        AIBinder_DeathRecipient_new(BinderDiedCallback));
  }

  /**
   * Gets the binder instance of ISEService, gets te reader corresponding to
   * secure element, establishes a session and opens a basic channel.
   */
  bool openConnection() override;
  /**
   * Opens Logical channel
   */
  virtual bool openChannel(std::vector<uint8_t>& aid, int8_t& channel_num,
                           std::vector<uint8_t>& select_resp) override;
  /**
   * Transmists the data over the opened basic channel and receives the data
   * back.
   */
  bool sendData(const vector<uint8_t>& inData,
                vector<uint8_t>& output) override;
  /**
   * Returns the state of the connection status. Returns true if the connection
   * is active, false if connection is broken.
   */
  bool isConnected() override;
  /**
   * Closes the opened channel.
   */
  bool closeChannel(uint8_t logical_channel_num) override;

  /**
   * Closes the connection.
   */
  void closeConnection();

 private:
  std::shared_ptr<aidl::android::se::omapi::ISecureElementService>
      omapiSeService;
  std::shared_ptr<aidl::android::se::omapi::ISecureElementReader> eSEReader;
  std::shared_ptr<aidl::android::se::omapi::ISecureElementSession> session;
  std::shared_ptr<aidl::android::se::omapi::ISecureElementChannel> channel;
  std::map<std::string,
           std::shared_ptr<aidl::android::se::omapi::ISecureElementReader>>
      mVSReaders;
  bool initialize();
  bool internalTransmitApdu(
      std::shared_ptr<aidl::android::se::omapi::ISecureElementReader> reader,
      std::vector<uint8_t> apdu, std::vector<uint8_t>& transmitResponse);

  ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;

  static void BinderDiedCallback(void* cookie);
  bool openChannelToApplet();
  inline uint16_t getApduStatus(std::vector<uint8_t>& inputData) {
    // Last two bytes are the status SW0SW1
    uint8_t SW0 = inputData.at(inputData.size() - 2);
    uint8_t SW1 = inputData.at(inputData.size() - 1);
    return (SW0 << 8 | SW1);
  }
};
}  // namespace se_update_agent
