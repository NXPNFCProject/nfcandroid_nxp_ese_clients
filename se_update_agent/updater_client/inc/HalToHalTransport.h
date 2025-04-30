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
 ** Copyright 2020-2021, 2025 NXP
 **
 *********************************************************************************/
#pragma once
#include <aidl/android/hardware/secure_element/BnSecureElementCallback.h>
#include <aidl/android/hardware/secure_element/ISecureElement.h>
#include <vector>
#include "ITransport.h"

namespace se_update_agent {
class SecureElementCallback;
using aidl::android::hardware::secure_element::ISecureElement;
using std::shared_ptr;
using std::vector;
/**
 * HalToHalTransport is derived from ITransport. This class gets the OMAPI
 * service binder instance and uses IPC to communicate with OMAPI service. OMAPI
 * inturn communicates with hardware via ISecureElement.
 */
class HalToHalTransport : public ITransport {
 public:
  HalToHalTransport() {}

  /**
   * Gets the binder instance of ISEService, gets the reader corresponding to
   * secure element, establishes a session.
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
   * Closes the given logical channel.
   */
  bool closeChannel(uint8_t channel_num) override;
  /**
   * Returns the state of the connection status. Returns true if the connection
   * is active, false if connection is broken.
   */
  bool isConnected() override;

  /**
   * Gets ATR info from eSE.
   */
  void getAtr(std::vector<uint8_t>& atr);

 private:
  std::vector<uint8_t> mAtr;
  std::shared_ptr<ISecureElement> mSecureElement;
  std::shared_ptr<SecureElementCallback> mSecureElementCallback;
  ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;
  static void BinderDiedCallback(void* cookie);
};
}  // namespace se_update_agent
