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

#ifndef SE_CONNECTION_H_
#define SE_CONNECTION_H_

#include <ITransport.h>

using se_update_agent::ITransport;

enum TransportType { HAL_TO_HAL, HAL_TO_OMAPI };

class SEConnection {
 public:
  /**
   * Gets Binder handle to eSEHAL/Omapi service
   */
  bool initialize();

  /**
   * Returns access to singleton instance of self
   * @param transport type
   */
  static SEConnection& getInstance(TransportType transport = HAL_TO_OMAPI);

  /**
   * Get ATR info from eSE
   */
  void getAtr(std::vector<uint8_t>& atr);

  /**
   *  Singleton instance
   * mark default constructor and copy operator delete
   */
  SEConnection(SEConnection const&) = delete;
  void operator=(SEConnection const&) = delete;
  std::shared_ptr<ITransport> transport_;

 private:
  SEConnection(TransportType transport_type);
  TransportType transport_type_;
};
#endif  // SE_CONNECTION_H_
