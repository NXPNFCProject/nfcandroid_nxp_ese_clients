/*******************************************************************************
 *
 *  Copyright 2025 NXP
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

#include <android-base/logging.h>

#include <HalToHalTransport.h>
#include <ITransport.h>
#include <OmapiTransport.h>
#include <SEConnection.h>

using se_update_agent::HalToHalTransport;
using se_update_agent::ITransport;
using se_update_agent::OmapiTransport;

bool SEConnection::initialize() { return transport_->openConnection(); }

SEConnection::SEConnection(TransportType transport)
    : transport_type_(transport) {
  LOG(INFO) << "Constructing SEConnection obj";
  if (transport_type_ == TransportType::HAL_TO_HAL) {
    transport_ = std::make_shared<HalToHalTransport>();
  } else {
    transport_ = std::make_shared<OmapiTransport>();
  }
  initialize();
  LOG(INFO) << "Constructed SEConnection obj";
}

void SEConnection::getAtr(std::vector<uint8_t>& atr) {
  LOG(INFO) << "Get ATR Info";
  transport_->getAtr(atr);
}
SEConnection& SEConnection::getInstance(TransportType transport) {
  static SEConnection instance(transport);
  return instance;
}
