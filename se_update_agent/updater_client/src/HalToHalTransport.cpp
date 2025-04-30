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
 ** Copyright 2020-2021, 2023,2025 NXP
 **
 *********************************************************************************/
#define LOG_TAG "HalToHalTransport"

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android/binder_manager.h>
#include <signal.h>
#include <iomanip>
#include <vector>

#include <HalToHalTransport.h>

#define LOGICAL_CH_NOT_SUPPORTED_SW1 0x68
#define LOGICAL_CH_NOT_SUPPORTED_SW2 0x81

using aidl::android::hardware::secure_element::BnSecureElementCallback;
using aidl::android::hardware::secure_element::ISecureElement;
using aidl::android::hardware::secure_element::LogicalChannelResponse;
using android::base::StringPrintf;
using ndk::ScopedAStatus;
using ndk::SharedRefBase;
using ndk::SpAIBinder;

namespace se_update_agent {

constexpr const char eseHalServiceName[] =
    "android.hardware.secure_element.ISecureElement/eSE1";

class SecureElementCallback : public BnSecureElementCallback {
 public:
  ScopedAStatus onStateChange(bool state,
                              const std::string& in_debugReason) override {
    std::string connected = state ? "true" : "false";
    LOG(INFO) << "connected =" << connected << "reason: " << in_debugReason;
    mConnState = state;
    return ScopedAStatus::ok();
  };
  bool isClientConnected() { return mConnState; }

 private:
  bool mConnState = false;
};

void HalToHalTransport::BinderDiedCallback(void* cookie) {
  LOG(ERROR) << "Received binder death ntf. SE HAL Service died";
  auto thiz = static_cast<HalToHalTransport*>(cookie);
  thiz->mSecureElementCallback->onStateChange(false, "SE HAL died");
  thiz->mSecureElement = nullptr;
}

bool HalToHalTransport::openConnection() {
  if (mSecureElement != nullptr &&
      mSecureElementCallback->isClientConnected()) {
    LOG(INFO) << "Already connected";
    return true;
  }
  bool connected = false;
  SpAIBinder binder =
      SpAIBinder(AServiceManager_waitForService(eseHalServiceName));
  mSecureElement = ISecureElement::fromBinder(binder);
  if (mSecureElement == nullptr) {
    LOG(ERROR) << "Failed to connect to Secure element service";
  } else {
    mSecureElementCallback = SharedRefBase::make<SecureElementCallback>();
    auto status = mSecureElement->init(mSecureElementCallback);
    connected = status.isOk() && mSecureElementCallback->isClientConnected();
    if (!connected) {
      LOG(ERROR) << "Failed to initialize SE HAL service";
    }
  }
  if (connected) {
    auto status = mSecureElement->getAtr(&mAtr);
    if (status.isOk()) {
      LOG(INFO) << "Got ATR Successfully";
    }
  }
  return connected;
}

bool HalToHalTransport::openChannel(std::vector<uint8_t>& aid,
                                    int8_t& channel_num,
                                    std::vector<uint8_t>& select_resp) {
  bool retval = false;
  LogicalChannelResponse logical_channel_response;
  auto status =
      mSecureElement->openLogicalChannel(aid, 0x00, &logical_channel_response);
  if (status.isOk()) {
    channel_num = logical_channel_response.channelNumber;
    select_resp = logical_channel_response.selectResponse;
    retval = true;
  } else {
    channel_num = -1;
    select_resp = logical_channel_response.selectResponse;
    LOG(ERROR) << "openLogicalChannel: Failed ";
  }
  return retval;
}

bool HalToHalTransport::sendData(const vector<uint8_t>& inData,
                                 vector<uint8_t>& output) {
  std::vector<uint8_t> cApdu(inData);
  if (!isConnected()) {
    if (!openConnection()) {
      return false;
    }
  }
  mSecureElement->transmit(inData, &output);

  if (output.size() < 2 ||
      (output.size() >= 2 &&
       (output.at(output.size() - 2) == LOGICAL_CH_NOT_SUPPORTED_SW1 &&
        output.at(output.size() - 1) == LOGICAL_CH_NOT_SUPPORTED_SW2))) {
    LOG(INFO) << "transmit failed";
    return false;
  }
  return true;
}

bool HalToHalTransport::closeChannel(uint8_t channel_num) {
  LOG(INFO) << "Channel number: " << static_cast<int>(channel_num);
  auto status = mSecureElement->closeChannel(channel_num);
  if (!status.isOk()) {
    /*
     * reason could be SE reset or HAL deinit triggered from other client
     * which anyway closes all the opened channels
     */
    LOG(ERROR) << "closeChannel failed";
  }
  return true;
}

bool HalToHalTransport::isConnected() {
  if (mSecureElement == nullptr ||
      !mSecureElementCallback->isClientConnected()) {
    return false;
  }
  return true;
}

void HalToHalTransport::getAtr(std::vector<uint8_t>& atr) { atr = this->mAtr; }
}  // namespace se_update_agent
